"""Full MITM proxy — aliases ALL known Futu server IPs, forwards to one real server."""
import os, socket, struct, select, sys, time, threading, subprocess
from pathlib import Path
from decimal import Decimal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from futu_moni.protocol import (
    build_extend_head, build_quote_request,
    decode_varint, CMD_LOGIN, CMD_QUOTE,
    HEADER_LENGTH, MAX_BODY_LENGTH, parse_quote_prices, Frame, encode_varint,
)

FORWARD_TO = "49.51.78.83"
FORWARD_PORT = 443

ALL_KNOWN_IPS = [
    "170.106.62.204", "170.106.48.217", "170.106.49.111", "170.106.201.247",
    "170.106.201.73",
    "43.130.30.145", "43.130.30.93",
    "43.175.134.104",
    "43.135.64.109", "43.135.82.18",
    "43.132.138.67",
    "43.152.136.145", "43.152.2.73",
    "43.159.177.6",
    "119.28.37.206", "119.28.37.77",
    "49.51.78.222", "49.51.78.82",
    "49.234.241.65",
    "124.156.234.231", "124.156.233.215",
    "129.226.111.140",
]

ALIAS_IPS = [ip for ip in ALL_KNOWN_IPS if ip != FORWARD_TO]

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
user_id = None
auth_remote = None
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


def handle_conn(csock, caddr, lip):
    global user_id, auth_remote
    print(f"  [{lip}] FTNN connected from {caddr[1]}")

    try:
        rsock = socket.create_connection((FORWARD_TO, FORWARD_PORT), timeout=10)
    except Exception as e:
        print(f"  [{lip}] Forward failed: {e}")
        csock.close()
        return

    uid = None
    logged = False

    try:
        while not stop.is_set():
            r, _, _ = select.select([csock, rsock], [], [], 1.0)
            for s in r:
                if s is csock:
                    d = csock.recv(65536)
                    if not d:
                        return
                    buf = bytearray(d)
                    off = 0
                    while off < len(buf):
                        res, noff = ft_frame(buf, off)
                        if not res:
                            break
                        cmd, fb, ext = res
                        off = noff
                        if cmd == CMD_LOGIN:
                            uid = struct.unpack(">I", fb[8:12])[0] >> 8
                            print(f"  [{lip}] LOGIN -> user=***{str(uid)[-3:]}")
                    rsock.sendall(d)

                elif s is rsock:
                    d = rsock.recv(65536)
                    if not d:
                        return
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
                                        user_id = uid
                                        auth_remote = rsock
                                    print(f"  [{lip}] *** LOGIN SUCCESS ***")
                                    login_done.set()
                                else:
                                    st = "BUSY" if rv == 0xFFFFFFFFFFFFFFFF else f"0x{rv:x}"
                                    print(f"  [{lip}] LOGIN result: {st}")
                    csock.sendall(d)
    except Exception as e:
        if not stop.is_set():
            print(f"  [{lip}] Error: {e}")
    finally:
        csock.close()
        if not logged:
            rsock.close()


def listener(ip):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((ip, 443))
    except Exception as e:
        return
    srv.listen(5)
    srv.settimeout(2.0)

    while not stop.is_set():
        try:
            c, a = srv.accept()
            threading.Thread(target=handle_conn, args=(c, a, ip), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break
    srv.close()


def inject():
    print("\n[inject] Waiting for login...")
    login_done.wait(timeout=120)
    if not login_done.is_set():
        print("[inject] Timeout - FTNN may have connected to an unknown server")
        stop.set()
        return

    time.sleep(5)
    with auth_lock:
        sock = auth_remote
        uid = user_id

    if not sock or not uid:
        print("[inject] No session")
        stop.set()
        return

    print(f"\n[inject] Querying JP ETFs (user=***{str(uid)[-3:]})")

    seq = 9000
    success_count = 0
    for rnd in range(1, 4):
        print(f"\n[inject] === Round {rnd}/3 ===")
        for sid, code in SECURITIES:
            ext = build_extend_head(os.urandom(32))
            req = build_quote_request(
                security_id=sid, route=1001, sequence=seq,
                user_id=uid, extend_head=ext,
            )
            try:
                sock.sendall(req)
                seq += 1

                hdr = bytearray()
                while len(hdr) < HEADER_LENGTH:
                    c = sock.recv(HEADER_LENGTH - len(hdr))
                    if not c:
                        print("[inject] Disconnected")
                        stop.set()
                        return
                    hdr.extend(c)

                blen = struct.unpack(">I", hdr[18:22])[0]
                elen = struct.unpack(">H", hdr[30:32])[0]
                rcmd = struct.unpack(">H", hdr[16:18])[0]

                body = bytearray()
                while len(body) < blen:
                    c = sock.recv(blen - len(body))
                    if not c:
                        break
                    body.extend(c)

                if rcmd == CMD_QUOTE:
                    payload = bytes(body[elen:])
                    if payload:
                        frame = Frame(command=rcmd, body=bytes(body), extend_head_length=elen)
                        try:
                            last, prev = parse_quote_prices(frame, security_id=sid)
                            print(f"[inject]   {code}: last={last} JPY, prev_close={prev} JPY")
                            success_count += 1
                        except Exception as e:
                            print(f"[inject]   {code}: parse error ({len(payload)}b payload)")
                    else:
                        print(f"[inject]   {code}: empty payload ({blen}b body, {elen}b ext)")
                else:
                    print(f"[inject]   {code}: cmd=0x{rcmd:04x}")
            except Exception as e:
                print(f"[inject]   {code}: {e}")
                stop.set()
                return
            time.sleep(0.5)
        time.sleep(2)

    print(f"\n[inject] Done! {success_count}/{3*len(SECURITIES)} quotes retrieved")
    query_done.set()
    time.sleep(3)
    stop.set()


def main():
    # Setup aliases
    print(f"[setup] Adding {len(ALIAS_IPS)} IP aliases...")
    for ip in ALIAS_IPS:
        os.system(f"ifconfig lo0 alias {ip} netmask 255.255.255.255 2>/dev/null")

    # Start listeners
    bound = 0
    for ip in ALIAS_IPS:
        t = threading.Thread(target=listener, args=(ip,), daemon=True)
        t.start()
        bound += 1
    print(f"[setup] {bound} listeners started, forwarding to {FORWARD_TO}:{FORWARD_PORT}")

    # Start injector
    threading.Thread(target=inject, daemon=True).start()

    time.sleep(1)
    print("[setup] Launching FTNN...")
    subprocess.Popen(["open", "/Applications/富途牛牛.app"])

    try:
        stop.wait(timeout=180)
    except KeyboardInterrupt:
        pass

    print("\n[cleanup] Removing aliases...")
    for ip in ALIAS_IPS:
        os.system(f"ifconfig lo0 -alias {ip} 2>/dev/null")

    subprocess.run(["pkill", "-9", "-f", "FTNN|富途牛牛"], capture_output=True)
    print("[cleanup] Done")

    if query_done.is_set():
        print("\n*** SUCCESS ***")
    else:
        print("\n*** FAILED — FTNN used an unknown server ***")


if __name__ == "__main__":
    main()
