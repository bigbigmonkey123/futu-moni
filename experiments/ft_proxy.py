"""Transparent TCP proxy for FT protocol — intercepts FTNN's session."""
import os, socket, struct, select, sys, time, threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from futu_moni.protocol import (
    build_extend_head, build_init_request, build_quote_request,
    encode_varint, decode_varint, CMD_LOGIN, CMD_QUOTE,
    HEADER_LENGTH, MAX_BODY_LENGTH,
)

REAL_SERVER = sys.argv[1] if len(sys.argv) > 1 else "170.106.62.204"
REAL_PORT = 443
LOCAL_PORT = 19443

def read_ft_frame(data, offset=0):
    if len(data) - offset < HEADER_LENGTH:
        return None, offset
    if data[offset:offset+2] != b"FT":
        return None, offset
    body_len = struct.unpack(">I", data[offset+18:offset+22])[0]
    total = HEADER_LENGTH + body_len
    if len(data) - offset < total:
        return None, offset
    cmd = struct.unpack(">H", data[offset+16:offset+18])[0]
    return (cmd, data[offset:offset+total]), offset + total

def proxy_session(client_sock, addr):
    print(f"[proxy] FTNN connected from {addr}")

    remote = socket.create_connection((REAL_SERVER, REAL_PORT), timeout=10)
    print(f"[proxy] Connected to {REAL_SERVER}:{REAL_PORT}")

    user_id = None
    logged_in = False
    query_done = threading.Event()

    client_buf = bytearray()
    remote_buf = bytearray()

    try:
        while True:
            readable, _, _ = select.select([client_sock, remote], [], [], 1.0)

            for sock in readable:
                if sock is client_sock:
                    data = client_sock.recv(65536)
                    if not data:
                        print("[proxy] FTNN disconnected")
                        return

                    client_buf.extend(data)
                    # Parse FT frames from client
                    offset = 0
                    while offset < len(client_buf):
                        result, new_offset = read_ft_frame(client_buf, offset)
                        if result is None:
                            break
                        cmd, frame = result
                        offset = new_offset

                        if cmd == CMD_LOGIN:
                            user_id = struct.unpack(">I", frame[8:12])[0] >> 8
                            print(f"[proxy] LOGIN detected, user=***{str(user_id)[-3:]}")

                    # Forward all data to server
                    remote.sendall(data)
                    client_buf = client_buf[offset:] if offset else client_buf

                elif sock is remote:
                    data = remote.recv(65536)
                    if not data:
                        print("[proxy] Server disconnected")
                        return

                    remote_buf.extend(data)
                    offset = 0
                    while offset < len(remote_buf):
                        result, new_offset = read_ft_frame(remote_buf, offset)
                        if result is None:
                            break
                        cmd, frame = result
                        offset = new_offset

                        if cmd == CMD_LOGIN:
                            ext_len = struct.unpack(">H", frame[30:32])[0]
                            payload = frame[HEADER_LENGTH + ext_len:]
                            if len(payload) >= 2:
                                _, p = decode_varint(payload, 0)
                                res, _ = decode_varint(payload, p)
                                if res == 0:
                                    logged_in = True
                                    print("[proxy] LOGIN SUCCESS — session authenticated")
                                else:
                                    print(f"[proxy] LOGIN failed: result=0x{res:x}")

                    remote_buf = remote_buf[offset:] if offset else remote_buf
                    # Forward to client
                    client_sock.sendall(data)

            # Once logged in, inject our queries
            if logged_in and not query_done.is_set():
                time.sleep(3)  # Wait for FTNN to finish its init
                print("[proxy] Injecting QUOTE queries...")

                import sqlite3
                db_path = Path.home() / ".com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat"
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                rows = conn.execute(
                    "SELECT id, code FROM security WHERE code IN ('1306','1321','1489') "
                    "AND market_code=830 AND delete_flag=0 AND delisted=0 ORDER BY code"
                ).fetchall()
                conn.close()

                seq = 9000  # High seq to avoid collisions with FTNN
                for attempt in range(3):
                    print(f"\n[proxy] === Query round {attempt+1} ===")
                    for sec_id, code in rows:
                        extend = build_extend_head(os.urandom(32))
                        quote_req = build_quote_request(
                            security_id=sec_id, route=1001, sequence=seq,
                            user_id=user_id, extend_head=extend,
                        )
                        remote.sendall(quote_req)
                        seq += 1

                        # Read response from server
                        resp_data = bytearray()
                        while len(resp_data) < HEADER_LENGTH:
                            chunk = remote.recv(65536)
                            if not chunk:
                                break
                            resp_data.extend(chunk)

                        if len(resp_data) >= HEADER_LENGTH:
                            r_body_len = struct.unpack(">I", resp_data[18:22])[0]
                            while len(resp_data) < HEADER_LENGTH + r_body_len:
                                chunk = remote.recv(65536)
                                if not chunk:
                                    break
                                resp_data.extend(chunk)

                            r_ext_len = struct.unpack(">H", resp_data[30:32])[0]
                            r_payload = resp_data[HEADER_LENGTH + r_ext_len:]
                            r_cmd = struct.unpack(">H", resp_data[16:18])[0]

                            if r_cmd == CMD_QUOTE and r_payload:
                                from futu_moni.protocol import parse_quote_prices, Frame
                                frame_obj = Frame(
                                    command=r_cmd,
                                    body=bytes(resp_data[HEADER_LENGTH:HEADER_LENGTH+r_body_len]),
                                    extend_head_length=r_ext_len,
                                )
                                try:
                                    last, prev = parse_quote_prices(frame_obj, security_id=sec_id)
                                    print(f"[proxy]   {code}: last={last} JPY, prev_close={prev} JPY")
                                except Exception as e:
                                    print(f"[proxy]   {code}: parse error ({len(r_payload)} bytes payload)")
                            else:
                                print(f"[proxy]   {code}: cmd=0x{r_cmd:04x}, payload={len(r_payload)} bytes")

                        time.sleep(0.3)

                    if attempt < 2:
                        time.sleep(2)

                query_done.set()
                print("\n[proxy] All queries done. Ctrl+C to exit.")

    except Exception as e:
        print(f"[proxy] Error: {e}")
    finally:
        client_sock.close()
        remote.close()

# Main server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", LOCAL_PORT))
server.listen(1)
print(f"[proxy] Listening on 127.0.0.1:{LOCAL_PORT}, forwarding to {REAL_SERVER}:{REAL_PORT}")
print(f"[proxy] Waiting for FTNN connection...")

try:
    client, addr = server.accept()
    proxy_session(client, addr)
except KeyboardInterrupt:
    print("\n[proxy] Shutting down")
finally:
    server.close()
