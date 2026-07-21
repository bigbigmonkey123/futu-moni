#!/usr/bin/env python3
"""
Lightweight transparent TCP proxy for FT protocol analysis.
Logs all bidirectional FT messages with protobuf decode.

Usage:
  1. Start proxy:  python3 ft_tcp_proxy.py --listen 8443 --target <server_ip>:443
  2. Redirect FTNN traffic via pfctl or socat
"""
import socket
import struct
import threading
import argparse
import sys
import time
import json
from datetime import datetime


def decode_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def decode_proto(data, depth=0):
    fields = {}
    pos = 0
    while pos < len(data):
        try:
            tag, pos = decode_varint(data, pos)
            fn = tag >> 3
            wt = tag & 7
            if fn == 0 or fn > 50000:
                break
            if wt == 0:
                val, pos = decode_varint(data, pos)
                fields.setdefault(fn, []).append(val)
            elif wt == 2:
                length, pos = decode_varint(data, pos)
                if pos + length > len(data) or length > 1000000:
                    break
                sub = data[pos:pos + length]
                pos += length
                if depth < 6:
                    sf = decode_proto(sub, depth + 1)
                    if sf:
                        fields.setdefault(fn, []).append(('msg', sf))
                    else:
                        fields.setdefault(fn, []).append(('bytes', sub.hex()))
                else:
                    fields.setdefault(fn, []).append(('bytes', sub.hex()))
            elif wt == 1:
                if pos + 8 > len(data): break
                pos += 8
            elif wt == 5:
                if pos + 4 > len(data): break
                pos += 4
            else:
                break
        except Exception:
            break
    return fields


def format_fields(fields, indent=0):
    lines = []
    pfx = "  " * indent
    JP_SIDS = {
        82669546513412: '.N225', 82669546513410: '.JPXN400',
        82669546513437: '.TOPIX', 82669546513451: '1306',
        82669546513459: '1321', 82669546513559: '1489',
    }
    for fn in sorted(fields.keys()):
        for v in fields[fn]:
            if isinstance(v, int):
                extra = ""
                if v in JP_SIDS:
                    extra = f"  <- {JP_SIDS[v]}"
                elif v > 1e15 and v < 1e20:
                    extra = f"  (price={v/1e9:.4f})"
                elif 1.7e12 < v < 2e12:
                    extra = f"  (ts)"
                lines.append(f"{pfx}f{fn}: {v}{extra}")
            elif isinstance(v, tuple):
                if v[0] == 'msg':
                    lines.append(f"{pfx}f{fn}: {{")
                    lines.append(format_fields(v[1], indent + 1))
                    lines.append(f"{pfx}}}")
                else:
                    b = v[1]
                    # Try to decode as UTF-8
                    try:
                        text = bytes.fromhex(b).decode('utf-8')
                        if text.isprintable() and len(text) > 2:
                            lines.append(f"{pfx}f{fn}: \"{text}\"")
                            continue
                    except:
                        pass
                    if len(b) <= 64:
                        lines.append(f"{pfx}f{fn}: [{len(b)//2}] {b}")
                    else:
                        lines.append(f"{pfx}f{fn}: [{len(b)//2}] {b[:48]}...")
    return "\n".join(lines)


CMD_NAMES = {
    0x1844: 'QUOTE_PUSH', 0x19C9: 'SNAPSHOT', 0x1773: 'CMD_1773',
    0x4EB8: 'CMD_4EB8', 0x1819: 'CMD_1819', 0x189D: 'CMD_189D',
    0x1843: 'CMD_1843', 0x1811: 'CMD_1811', 0x125C: 'HEARTBEAT',
    0x03EB: 'CMD_03EB', 0x1B0E: 'CMD_1B0E', 0x24F0: 'CMD_24F0',
}


class FTStreamParser:
    def __init__(self, label):
        self.buf = bytearray()
        self.label = label
        self.msg_count = 0

    def feed(self, data):
        self.buf.extend(data)
        messages = []
        while len(self.buf) >= 32:
            idx = self.buf.find(b'FT')
            if idx < 0:
                self.buf.clear()
                break
            if idx > 0:
                self.buf = self.buf[idx:]
            if len(self.buf) < 32:
                break
            hdr = bytes(self.buf[:32])
            cmd = struct.unpack('>H', hdr[16:18])[0]
            body_len = struct.unpack('>I', hdr[18:22])[0]
            if body_len == 0 or body_len > 500000:
                self.buf = self.buf[2:]
                continue
            total = 32 + body_len
            if len(self.buf) < total:
                break
            body = bytes(self.buf[32:total])
            seq = struct.unpack('>I', hdr[12:16])[0]
            self.msg_count += 1
            messages.append({
                'cmd': cmd, 'seq': seq, 'body': body,
                'header': hdr, 'n': self.msg_count,
            })
            self.buf = self.buf[total:]
        return messages


# Global log file
log_file = None
log_lock = threading.Lock()


def log_msg(direction, msg, verbose=True):
    cmd = msg['cmd']
    cmd_name = CMD_NAMES.get(cmd, f'0x{cmd:04X}')
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    seq = msg['seq']
    body = msg['body']

    fields = decode_proto(body)
    proto_str = format_fields(fields, indent=1)

    output = (
        f"\n{'='*70}\n"
        f"[{ts}] {direction} #{msg['n']}  cmd={cmd_name}(0x{cmd:04X})  "
        f"seq={seq}  body={len(body)}b\n"
        f"  hdr: {msg['header'].hex()}\n"
    )

    if proto_str:
        output += proto_str + "\n"
    else:
        output += f"  raw: {body[:60].hex()}\n"

    if verbose:
        print(output, flush=True)

    with log_lock:
        if log_file:
            log_file.write(output + "\n")
            log_file.flush()

    # Save raw message for replay analysis
    return {
        'time': ts, 'direction': direction,
        'cmd': f'0x{cmd:04X}', 'cmd_name': cmd_name,
        'seq': seq, 'header': msg['header'].hex(),
        'body': body.hex(), 'body_len': len(body),
    }


def relay(src, dst, parser, direction, raw_log, quiet_cmds=None):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            for m in parser.feed(data):
                cmd = m['cmd']
                if quiet_cmds and cmd in quiet_cmds:
                    continue
                entry = log_msg(direction, m)
                raw_log.append(entry)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass


def handle_client(client_sock, target_host, target_port, raw_log):
    addr = client_sock.getpeername()
    print(f"\n[CONN] Client connected: {addr}", flush=True)

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(10)
        server_sock.connect((target_host, target_port))
        server_sock.settimeout(None)
        print(f"[CONN] Connected to server: {target_host}:{target_port}", flush=True)
    except Exception as e:
        print(f"[ERROR] Cannot connect to server: {e}", flush=True)
        client_sock.close()
        return

    c2s_parser = FTStreamParser("C->S")
    s2c_parser = FTStreamParser("S->C")

    quiet = {0x125C}  # suppress heartbeat spam

    t1 = threading.Thread(target=relay, args=(client_sock, server_sock, c2s_parser, "C->S", raw_log, quiet))
    t2 = threading.Thread(target=relay, args=(server_sock, client_sock, s2c_parser, "S->C", raw_log, quiet))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print(f"[CONN] Connection closed: {addr}  (C->S: {c2s_parser.msg_count}, S->C: {s2c_parser.msg_count})", flush=True)


def main():
    p = argparse.ArgumentParser(description='FT protocol TCP proxy')
    p.add_argument('--listen', '-l', type=int, default=8443, help='Local listen port')
    p.add_argument('--target', '-t', default='170.106.62.204:443',
                   help='Target server host:port')
    p.add_argument('--log', default='/tmp/ft_proxy.log', help='Log file path')
    p.add_argument('--raw-log', default='/tmp/ft_proxy_raw.jsonl', help='Raw message log (JSONL)')
    args = p.parse_args()

    target_parts = args.target.split(':')
    target_host = target_parts[0]
    target_port = int(target_parts[1]) if len(target_parts) > 1 else 443

    global log_file
    log_file = open(args.log, 'w')

    raw_log = []

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', args.listen))
    server.listen(5)

    print(f"FT Protocol Proxy")
    print(f"  Listen: 127.0.0.1:{args.listen}")
    print(f"  Target: {target_host}:{target_port}")
    print(f"  Log:    {args.log}")
    print(f"  Raw:    {args.raw_log}")
    print(f"\nWaiting for connections... (Ctrl+C to stop)\n")

    try:
        while True:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client,
                                 args=(client, target_host, target_port, raw_log))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print(f"\n\nStopping. {len(raw_log)} messages captured.")
        with open(args.raw_log, 'w') as f:
            for entry in raw_log:
                f.write(json.dumps(entry) + "\n")
        print(f"Raw log saved: {args.raw_log}")
    finally:
        server.close()
        if log_file:
            log_file.close()


if __name__ == '__main__':
    main()
