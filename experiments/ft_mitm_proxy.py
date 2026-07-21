"""MITM proxy using lo0 IP aliasing — intercepts FTNN's FT protocol session.

Listens on aliased Futu server IPs (bound to lo0), forwards to a real Futu server,
intercepts LOGIN for authentication, then injects QUOTE queries.
"""
import os, socket, struct, select, sys, time, threading, signal
from pathlib import Path
from decimal import Decimal

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from futu_moni.protocol import (
    build_extend_head, build_init_request, build_quote_request,
    decode_varint, CMD_LOGIN, CMD_QUOTE, CMD_INIT,
    HEADER_LENGTH, MAX_BODY_LENGTH, parse_quote_prices, Frame,
)

REAL_SERVER = "170.106.62.204"
REAL_PORT = 443

ALIAS_IPS = [
    "49.51.78.83",
    "119.28.37.206",
    "43.130.30.145",
    "43.175.134.104",
    "129.226.111.140",
    "170.106.49.111",
    "170.106.201.73",
    "170.106.201.247",
    "170.106.48.217",
    "43.159.177.6",
]

import sqlite3
db_path = Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat"
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
SECURITIES = conn.execute(
    "SELECT id, code FROM security WHERE code IN ('1306','1321','1489') "
    "AND market_code=830 AND delete_flag=0 AND delisted=0 ORDER BY code"
).fetchall()
conn.close()

stop_event = threading.Event()
login_captured = threading.Event()
user_id = None
authenticated_remote = None
auth_lock = threading.Lock()


def read_ft_frame_from_buf(data, offset=0):
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
    ext_len = struct.unpack(">H", data[offset+30:offset+32])[0]
    return (cmd, bytes(data[offset:offset+total]), ext_len), offset + total


def proxy_connection(client_sock, client_addr, listen_ip):
    global user_id, authenticated_remote
    print(f"[proxy] Connection from {client_addr} (intended for {listen_ip})")

    try:
        remote = socket.create_connection((REAL_SERVER, REAL_PORT), timeout=10)
        print(f"[proxy] Connected to real server {REAL_SERVER}:{REAL_PORT}")
    except Exception as e:
        print(f"[proxy] Failed to connect to real server: {e}")
        client_sock.close()
        return

    local_user_id = None
    local_logged_in = False

    try:
        while not stop_event.is_set():
            readable, _, _ = select.select([client_sock, remote], [], [], 1.0)

            for sock in readable:
                if sock is client_sock:
                    data = client_sock.recv(65536)
                    if not data:
                        print(f"[proxy] Client disconnected ({listen_ip})")
                        return

                    # Scan for FT LOGIN in outbound data
                    buf = bytearray(data)
                    offset = 0
                    while offset < len(buf):
                        result, new_offset = read_ft_frame_from_buf(buf, offset)
                        if result is None:
                            break
                        cmd, frame_bytes, ext_len = result
                        offset = new_offset
                        if cmd == CMD_LOGIN:
                            uid = struct.unpack(">I", frame_bytes[8:12])[0] >> 8
                            local_user_id = uid
                            print(f"[proxy] LOGIN detected -> user=***{str(uid)[-3:]}")

                    # Forward to real server
                    remote.sendall(data)

                elif sock is remote:
                    data = remote.recv(65536)
                    if not data:
                        print(f"[proxy] Server disconnected ({listen_ip})")
                        return

                    # Check for LOGIN response
                    buf = bytearray(data)
                    offset = 0
                    while offset < len(buf):
                        result, new_offset = read_ft_frame_from_buf(buf, offset)
                        if result is None:
                            break
                        cmd, frame_bytes, ext_len = result
                        offset = new_offset
                        if cmd == CMD_LOGIN:
                            payload = frame_bytes[HEADER_LENGTH + ext_len:]
                            if len(payload) >= 2:
                                _, p = decode_varint(payload, 0)
                                res, _ = decode_varint(payload, p)
                                if res == 0:
                                    local_logged_in = True
                                    with auth_lock:
                                        user_id = local_user_id
                                        authenticated_remote = remote
                                    print(f"[proxy] *** LOGIN SUCCESS on {listen_ip} ***")
                                    login_captured.set()
                                else:
                                    status = "BUSY" if res == 0xFFFFFFFFFFFFFFFF else f"0x{res:x}"
                                    print(f"[proxy] LOGIN failed on {listen_ip}: {status}")

                    # Forward to client
                    client_sock.sendall(data)

    except Exception as e:
        if not stop_event.is_set():
            print(f"[proxy] Connection error ({listen_ip}): {e}")
    finally:
        client_sock.close()
        if not local_logged_in:
            remote.close()


def listener_thread(ip):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((ip, 443))
    except Exception as e:
        print(f"[proxy] Cannot bind {ip}:443 - {e}")
        return
    server.listen(5)
    server.settimeout(2.0)
    print(f"[proxy] Listening on {ip}:443")

    while not stop_event.is_set():
        try:
            client, addr = server.accept()
            t = threading.Thread(target=proxy_connection, args=(client, addr, ip), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                print(f"[proxy] Accept error on {ip}: {e}")
            break

    server.close()


def inject_queries():
    """Once authenticated, inject QUOTE queries on the authenticated connection."""
    print("\n[inject] Waiting for authenticated session...")
    login_captured.wait(timeout=120)
    if not login_captured.is_set():
        print("[inject] Timeout waiting for login")
        return

    time.sleep(5)  # Let FTNN finish its init sequence

    with auth_lock:
        remote = authenticated_remote
        uid = user_id

    if remote is None or uid is None:
        print("[inject] No authenticated session available")
        return

    print(f"\n[inject] === Injecting QUOTE queries (user=***{str(uid)[-3:]}) ===")

    seq = 9000
    for attempt in range(1, 4):
        print(f"\n[inject] --- Round {attempt}/3 ---")
        for sec_id, code in SECURITIES:
            extend = build_extend_head(os.urandom(32))
            req = build_quote_request(
                security_id=sec_id, route=1001, sequence=seq,
                user_id=uid, extend_head=extend,
            )
            try:
                remote.sendall(req)
                seq += 1

                # Read response
                resp_header = bytearray()
                while len(resp_header) < HEADER_LENGTH:
                    chunk = remote.recv(HEADER_LENGTH - len(resp_header))
                    if not chunk:
                        print(f"[inject] Connection closed")
                        return
                    resp_header.extend(chunk)

                r_body_len = struct.unpack(">I", resp_header[18:22])[0]
                r_ext_len = struct.unpack(">H", resp_header[30:32])[0]
                r_cmd = struct.unpack(">H", resp_header[16:18])[0]

                resp_body = bytearray()
                while len(resp_body) < r_body_len:
                    chunk = remote.recv(r_body_len - len(resp_body))
                    if not chunk:
                        break
                    resp_body.extend(chunk)

                if r_cmd == CMD_QUOTE:
                    r_payload = bytes(resp_body[r_ext_len:])
                    if r_payload:
                        frame = Frame(command=r_cmd, body=bytes(resp_body), extend_head_length=r_ext_len)
                        try:
                            last, prev = parse_quote_prices(frame, security_id=sec_id)
                            print(f"[inject]   {code}: last={last} JPY, prev_close={prev} JPY")
                        except Exception as e:
                            print(f"[inject]   {code}: parse error ({len(r_payload)} bytes)")
                    else:
                        print(f"[inject]   {code}: empty payload")
                else:
                    print(f"[inject]   {code}: unexpected cmd=0x{r_cmd:04x}")

            except Exception as e:
                print(f"[inject]   {code}: error - {e}")
                return

            time.sleep(0.5)

        if attempt < 3:
            time.sleep(3)

    print("\n[inject] *** All 3 rounds completed! ***")
    stop_event.set()


def main():
    # Setup IP aliases
    print("[setup] Adding IP aliases on lo0...")
    for ip in ALIAS_IPS:
        os.system(f"ifconfig lo0 alias {ip} netmask 255.255.255.255 2>/dev/null")
    print(f"[setup] {len(ALIAS_IPS)} aliases configured")

    # Start listeners
    threads = []
    for ip in ALIAS_IPS:
        t = threading.Thread(target=listener_thread, args=(ip,), daemon=True)
        t.start()
        threads.append(t)

    # Start injector thread
    injector = threading.Thread(target=inject_queries, daemon=True)
    injector.start()

    time.sleep(1)
    print(f"\n[setup] Proxy ready. Forwarding to {REAL_SERVER}:{REAL_PORT}")
    print("[setup] Now launching FTNN...")

    import subprocess
    subprocess.Popen(["open", "/Applications/富途牛牛.app"])

    # Wait for completion or timeout
    try:
        stop_event.wait(timeout=180)
    except KeyboardInterrupt:
        pass

    print("\n[cleanup] Shutting down...")
    stop_event.set()

    # Remove aliases
    for ip in ALIAS_IPS:
        os.system(f"ifconfig lo0 -alias {ip} 2>/dev/null")
    print("[cleanup] IP aliases removed")

    # Kill FTNN
    os.system("pkill -9 -f 'FTNN|富途牛牛' 2>/dev/null")


if __name__ == "__main__":
    main()
