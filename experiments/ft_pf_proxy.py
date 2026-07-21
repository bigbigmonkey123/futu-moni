"""MITM proxy using PF rdr + route — intercepts FTNN's FT protocol login,
then injects JP ETF QUOTE queries on the authenticated connection.

Approach:
1. Add host routes for known Futu server IPs → lo0
2. PF rdr on lo0 redirects port 443 → 127.0.0.1:19443
3. This proxy on 19443 forwards to a real Futu server (not route-trapped)
4. Intercepts LOGIN success, then injects QUOTE queries
"""
import os, socket, struct, select, sys, time, threading, subprocess
from pathlib import Path
from decimal import Decimal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from futu_moni.protocol import (
    build_extend_head, build_quote_request,
    decode_varint, CMD_LOGIN, CMD_QUOTE,
    HEADER_LENGTH, MAX_BODY_LENGTH, parse_quote_prices, Frame, encode_varint,
)

FORWARD_TO = "119.28.37.206"
FORWARD_PORT = 443

ALL_KNOWN = [
    "170.106.62.204", "170.106.48.217", "170.106.49.111",
    "170.106.201.247", "170.106.201.73",
    "43.130.30.145", "43.130.30.93",
    "43.175.134.104",
    "43.135.64.109", "43.135.82.18",
    "43.132.138.67",
    "43.152.136.145", "43.152.2.73",
    "43.159.177.6",
    "119.28.37.206", "119.28.37.77",
    "49.51.78.222", "49.51.78.82", "49.51.78.83",
    "49.234.241.65",
    "124.156.234.231", "124.156.233.215",
    "129.226.111.140",
]
TRAP_IPS = [ip for ip in ALL_KNOWN if ip != FORWARD_TO]

import sqlite3
db_path = Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat"
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
SECURITIES = conn.execute(
    "SELECT id, code FROM security WHERE code IN ('1306','1321','1489') "
    "AND market_code=830 AND delete_flag=0 AND delisted=0 ORDER BY code"
).fetchall()
conn.close()

stop = threading.Event()
login_done = threading.Event()
query_done = threading.Event()
user_id_val = None
auth_remote_sock = None
auth_lock = threading.Lock()


def ft_frame(data, offset=0):
    if len(data) - offset < HEADER_LENGTH:
        return None, offset
    if data[offset:offset+2] != b"FT" or data[offset+2] != 0x27:
        return None, offset
    body_len = struct.unpack(">I", data[offset+18:offset+22])[0]
    if body_len > MAX_BODY_LENGTH:
        return None, offset
    total = HEADER_LENGTH + body_len
    if len(data) - offset < total:
        return None, offset
    cmd = struct.unpack(">H", data[offset+16:offset+18])[0]
    ext = struct.unpack(">H", data[offset+30:offset+32])[0]
    return (cmd, bytes(data[offset:offset+total]), ext), offset + total


def handle(csock, caddr):
    global user_id_val, auth_remote_sock
    print(f"  FTNN connected ({caddr[0]}:{caddr[1]})")

    try:
        rsock = socket.create_connection((FORWARD_TO, FORWARD_PORT), timeout=10)
        print(f"  -> forwarding to {FORWARD_TO}:{FORWARD_PORT}")
    except Exception as e:
        print(f"  Forward failed: {e}")
        csock.close()
        return

    uid = None
    logged = False
    conn_id = caddr[1]

    try:
        while not stop.is_set():
            r, _, _ = select.select([csock, rsock], [], [], 1.0)
            for s in r:
                if s is csock:
                    d = csock.recv(65536)
                    if not d:
                        return
                    # Scan for FT frames in outbound data
                    buf = bytearray(d)
                    off = 0
                    while off < len(buf):
                        res, noff = ft_frame(buf, off)
                        if not res:
                            break
                        cmd, fb, ext = res
                        off = noff
                        cmd_names = {0x1771: "LOGIN", 0x1B0E: "INIT", 0x1AA8: "QUOTE"}
                        cname = cmd_names.get(cmd, f"0x{cmd:04x}")
                        if cmd in (CMD_LOGIN, 0x1B0E):
                            print(f"  [{conn_id}] OUT: {cname} ({len(fb)}b)")
                        if cmd == CMD_LOGIN:
                            uid = struct.unpack(">I", fb[8:12])[0] >> 8
                            print(f"  [{conn_id}] LOGIN detected (user=***{str(uid)[-3:]})")
                    rsock.sendall(d)
                elif s is rsock:
                    d = rsock.recv(65536)
                    if not d:
                        return
                    # Check LOGIN response
                    buf = bytearray(d)
                    off = 0
                    while off < len(buf):
                        res, noff = ft_frame(buf, off)
                        if not res:
                            break
                        cmd, fb, ext = res
                        off = noff
                        if cmd == CMD_LOGIN and uid:
                            payload = fb[HEADER_LENGTH + ext:]
                            if len(payload) >= 2:
                                _, p = decode_varint(payload, 0)
                                rv, _ = decode_varint(payload, p)
                                if rv == 0:
                                    logged = True
                                    with auth_lock:
                                        user_id_val = uid
                                        auth_remote_sock = rsock
                                    print(f"  *** LOGIN SUCCESS ***")
                                    login_done.set()
                                else:
                                    st = "BUSY" if rv == 0xFFFFFFFFFFFFFFFF else f"0x{rv:x}"
                                    print(f"  LOGIN result: {st}")
                    csock.sendall(d)
                    if logged:
                        # Hand off remote socket to inject thread; stop proxy loop
                        csock.close()
                        return
    except Exception as e:
        if not stop.is_set():
            print(f"  Connection error: {e}")
    finally:
        csock.close()
        if not logged:
            rsock.close()


def inject():
    print("\n[query] Waiting for authenticated session...")
    login_done.wait(timeout=120)
    if not login_done.is_set():
        print("[query] Timeout — no login intercepted")
        stop.set()
        return

    time.sleep(5)
    with auth_lock:
        sock = auth_remote_sock
        uid = user_id_val

    print(f"\n[query] Injecting JP ETF queries (user=***{str(uid)[-3:]})")
    seq = 9000
    ok = 0

    def read_one_frame(s):
        hdr = bytearray()
        while len(hdr) < HEADER_LENGTH:
            c = s.recv(HEADER_LENGTH - len(hdr))
            if not c:
                return None
            hdr.extend(c)
        blen = struct.unpack(">I", hdr[18:22])[0]
        elen = struct.unpack(">H", hdr[30:32])[0]
        rcmd = struct.unpack(">H", hdr[16:18])[0]
        rseq = struct.unpack(">I", hdr[12:16])[0]
        body = bytearray()
        while len(body) < blen:
            c = s.recv(blen - len(body))
            if not c:
                return None
            body.extend(c)
        return rcmd, rseq, elen, bytes(body)

    for rnd in range(1, 4):
        print(f"\n[query] --- Round {rnd}/3 ---")
        for sid, code in SECURITIES:
            ext = build_extend_head(os.urandom(32))
            req = build_quote_request(
                security_id=sid, route=1001, sequence=seq,
                user_id=uid, extend_head=ext,
            )
            my_seq = seq
            seq += 1
            try:
                sock.sendall(req)
                # Read frames until we get our QUOTE response (matching sequence)
                found = False
                for _ in range(50):  # max 50 frames to skip
                    result = read_one_frame(sock)
                    if result is None:
                        print("[query] Disconnected")
                        stop.set()
                        return
                    rcmd, rseq, elen, body = result
                    if rcmd == CMD_QUOTE and rseq == my_seq:
                        payload = body[elen:]
                        if payload:
                            frame = Frame(command=rcmd, body=body, extend_head_length=elen)
                            try:
                                last, prev = parse_quote_prices(frame, security_id=sid)
                                print(f"[query]   {code}: last={last} JPY, prev_close={prev} JPY")
                                ok += 1
                            except:
                                print(f"[query]   {code}: parse error ({len(payload)}b)")
                        else:
                            print(f"[query]   {code}: empty payload")
                        found = True
                        break
                if not found:
                    print(f"[query]   {code}: response not found in 50 frames")
            except Exception as e:
                print(f"[query]   {code}: {e}")
                stop.set()
                return
            time.sleep(0.3)
        time.sleep(2)

    print(f"\n[query] Done: {ok}/{3*len(SECURITIES)} successful quotes")
    query_done.set()
    time.sleep(3)
    stop.set()


def setup():
    # Check port 443 not occupied
    result = subprocess.run(["lsof", "-nP", "-iTCP:443"], capture_output=True, text=True)
    if "LISTEN" in result.stdout:
        print("ERROR: Port 443 already in use!")
        for line in result.stdout.split("\n"):
            if "LISTEN" in line:
                print(f"  {line}")
        return False

    # Add routes
    print(f"[setup] Adding {len(TRAP_IPS)} host routes to lo0...")
    for ip in TRAP_IPS:
        os.system(f"route add -host {ip} -interface lo0 2>/dev/null")

    # Load PF rules
    pf_rules = "rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port 19443\n"
    proc = subprocess.run(
        ["pfctl", "-ef", "-"],
        input=pf_rules, capture_output=True, text=True
    )
    if proc.returncode != 0:
        print(f"[setup] PF error: {proc.stderr}")
    else:
        print("[setup] PF rdr rule loaded")
    return True


def cleanup():
    print("\n[cleanup] Removing routes and PF rules...")
    subprocess.run(["pfctl", "-d"], capture_output=True)
    for ip in TRAP_IPS:
        os.system(f"route delete -host {ip} 2>/dev/null")
    subprocess.run(["pkill", "-9", "-f", "FTNN|富途牛牛"], capture_output=True)
    print("[cleanup] Done")


def main():
    if not setup():
        return

    # Listener
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 19443))
    srv.listen(10)
    srv.settimeout(2.0)
    print(f"[proxy] Listening on 127.0.0.1:19443 -> {FORWARD_TO}:{FORWARD_PORT}")

    threading.Thread(target=inject, daemon=True).start()

    time.sleep(1)
    print("[proxy] Launching FTNN...")
    subprocess.Popen(["open", "/Applications/富途牛牛.app"])

    try:
        while not stop.is_set():
            try:
                c, a = srv.accept()
                threading.Thread(target=handle, args=(c, a), daemon=True).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        pass

    srv.close()
    cleanup()

    if query_done.is_set():
        print("\n*** SUCCESS: JP ETF quotes retrieved! ***")
    else:
        print("\n*** INCOMPLETE ***")


if __name__ == "__main__":
    main()
