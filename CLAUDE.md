# futu-moni

MITM proxy that intercepts FTNN (富途牛牛) desktop app's native FT binary protocol to obtain JP ETF quotes (1306, 1321, 1489). **No OpenD allowed — native app only.**

## Quick Start (Development)

```bash
uv sync                        # install deps
uv pip install pytest          # no test extra declared
uv run pytest tests/ -v        # run all tests (28 tests, no root needed)
```

Entry point: `python -m futu_moni` (NOT `futu_moni.main`). Requires root.

## Hard Constraints

- **No OpenD** — must use FTNN native app's network channel
- **No DNS** — FTNN resolves FT servers via hardcoded IPs + protobuf API, not DNS
- **One-time token** — LOGIN token is consumed server-side; packet replay never works
- **Root required** — route/pfctl/lsof need root privileges
- **macOS only** — depends on pfctl, route, lsof

## Architecture (v0.7: route-lift + ConnIpRsp + LOGIN redirect + passthrough)

```
                    FTNN                          Real Server
                     │                                │
                     │ connect(IP:443)                │
                     ▼                                │
              ┌─── lo0 ───┐                           │
              │ route trap │                          │
              └─────┬──────┘                          │
                    │ PF anchor rdr                   │
                    ▼                                 │
             proxy :19443                             │
                    │                                 │
                    │ route-lift: delete→connect→add   │
                    ├────────────────────────────────►│
                    │                                 │
                    │◄─── ConnIpRsp (parse IPs) ──────│
                    │     hot-add route for new IPs   │
                    │                                 │
                    │◄─── LOGIN response ─────────────│
                    │     if result==0: keep socket   │
                    │                                 │
              cleanup routes + PF                     │
                    │                                 │
              ProxyQuoteClient                        │
                    │──── INIT req ──────────────────►│
                    │◄─── INIT rsp ──────────────────│
                    │──── QUOTE req ─────────────────►│
                    │◄─── QUOTE rsp ─────────────────│
```

### Step-by-step

1. **Load IP pool** (~159 IPs): `strings F3CLogin.framework` (~155) + `sqlite3 CommonConfig.db guaranteed_ip_for_conn` (~54), deduped
2. **Route trap**: `route add -host <IP> -interface lo0` for each IP
3. **PF anchor**: `pfctl -a stock-moni -f -` → `rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port 19443`
4. **Launch FTNN**: `killall FTNN` + pgrep polling (up to 10s, SIGKILL fallback) + `open -a /Applications/富途牛牛.app`
5. **Accept connection**: FTNN → lo0 → PF → proxy:19443. Non-FT connections (TLS/HTTPS) auto-switch to passthrough mode
6. **Route-lift upstream connect**: `route delete -host <IP>` → `socket.connect(IP:443)` → `route add -host <IP> -interface lo0` (race window <100ms)
7. **Parse response frames**: if `command ∈ CMD_CONNIP {0xFFE1, 0x0529, 0x4EB3}` → `extract_connip_ips(payload)` → `_hot_add_route(ip)`
8. **LOGIN intercept**: detect LOGIN request (extract user_id from header[8:12]>>8), detect LOGIN response. result==0 → success. result==1 → redirect: parse redirect IP from response protobuf, hot-add route, wait for FTNN to retry on redirect server
9. **Socket handoff**: close client side, keep proxy↔server socket as `ProxySession`
10. **Cleanup**: delete all routes + `pfctl -a stock-moni -F all`
11. **Query**: `ProxyQuoteClient` sends INIT + QUOTE on the kept socket, sequence starts at 9001

### Why route-lift (not IP_BOUND_IF)

Earlier approach used `setsockopt(IP_BOUND_IF=25)` to bind upstream socket to physical NIC (en1), bypassing lo0. **This conflicts with route traps** — kernel sees route→lo0 but socket bound to en1, returns `EADDRNOTAVAIL`. Route-lift (temporarily remove and restore the host route) avoids this conflict.

### Why ConnIpRsp in-proxy parsing (not just lsof)

lsof runs every 3s. ConnIpRsp tells FTNN about new server IPs. If FTNN connects to a new IP before lsof discovers it, the connection bypasses the trap. In-proxy parsing sees ConnIpRsp frames **before** forwarding them to FTNN, so routes are added before FTNN can use the IPs.

### Why passthrough mode for non-FT connections

FTNN opens both FT binary (port 443, no TLS) and TLS/HTTPS connections to the same IPs. v0.6 crashed on non-FT data (`framing_error`), killing the connection thread **before** `sendall` could forward the data — breaking FTNN's TLS connections entirely. v0.7 detects non-FT magic bytes and switches to transparent forwarding.

### Why LOGIN redirect handling

LOGIN result=1 means "redirect to another server" (the response contains a redirect IP in a protobuf string field). v0.6 treated any non-zero result as final failure. v0.7 parses the redirect IP from the response protobuf, hot-adds a route **before** forwarding the response to FTNN, then waits for FTNN to retry LOGIN on the redirect server.

## FT Binary Protocol

### Frame format (32-byte header)

```
Offset  Size  Field            Notes
 0      2B    magic            "FT" (0x46 0x54)
 2      1B    proto_version    0x27
 3      1B    flags            0x6F
 4      2B    reserved_1       0x41A8
 6      2B    reserved_2       0x0200
 8      4B    user_id_shifted  user_id << 8
12      4B    sequence         big-endian, request/response pairing
16      2B    command          see table below
18      4B    body_length      big-endian, max 1MB
22      8B    reserved_3       0
30      2B    extend_length    bytes of extend_head within body
```

`body = extend_head + payload` (both protobuf)

### Commands

| Command | Code | Direction | Notes |
|---------|------|-----------|-------|
| LOGIN | 0x1771 | bidirectional | one-time token, result: 0=ok, 1=redirect (contains IP), 0xFFFFFFFFFFFFFFFF=busy |
| INIT | 0x1B0E | bidirectional | must send after LOGIN success |
| QUOTE | 0x1AA8 | bidirectional | security_id + selectors → prices in nanounits (÷1e9=JPY) |
| Heartbeat | 0x1844 | server→client | skip when reading |
| ConnIpRsp | 0xFFE1, 0x0529, 0x4EB3 | server→client | IP pool assignment |

### ConnIpRsp protobuf

```
ConnIpRsp:
  field 1 (varint):  result_code     // tag 0x08
  field 2 (string):  unknown         // tag 0x12
  field 3 (repeated ConnIpItem):     // tag 0x1a

ConnIpItem:
  field 1 (string):  server_ip       // tag 0x0a  ← extract this
  field 2 (varint):  port            // tag 0x10
  field 5 (varint):  conn_identity   // tag 0x28, 0x64 = main channel
```

### LOGIN response payload

```python
_, pos = decode_varint(payload, 0)   # field tag (0x08)
result, _ = decode_varint(payload, pos)
# result == 0 → LOGIN_OK
# result == 1 → LOGIN_REDIRECT (field 5 = redirect server IP string)
# result == 0xFFFFFFFFFFFFFFFF → LOGIN_BUSY
# other → LOGIN_REJECTED
```

LOGIN redirect response example (field 5 = "49.51.78.83", field 6 = 443):
```
08 01 2a 0b "49.51.78.83" 30 bb03 40 01 50 00
```

## IP Resolution Chain (priority high→low)

1. **F3CLogin.framework hardcoded**: ~155 public IPs compiled in binary
2. **ConnIpRsp**: online IP assignment via FT protocol (protobuf)
3. **Cloud config confnn.futuhn.com**: overrides SQLite guaranteed_ip
4. **guaranteed_ip_for_conn**: CommonConfig.db fallback pool
5. **forced_ip_for_conn**: not enabled

## File Map

| File | Role | Risk |
|------|------|------|
| `proxy.py` | Core: IP pool, route/PF setup, route-lift connect, ConnIpRsp parser, LOGIN redirect, passthrough, lsof monitor | HIGH — system-level changes |
| `protocol.py` | FT binary: header build/parse, varint, frame read/write, quote price decode | HIGH — one byte offset breaks everything |
| `experiments/ft_market_probe.py` | Sanitized read-only selector 0/1/2 shape probe; never emits opaque payload/account material | MEDIUM |
| `experiments/ft_selector_probe.py` | Sanitized read-only selector inventory; `--all-symbols-key` verifies selectors 0/3/4/5/6/7/8 for all targets | MEDIUM |
| `adapter.py` | `ProxyQuoteClient` (post-MITM queries), security_id resolution from SecListDB | MEDIUM |
| `models.py` | Pydantic models, fail-closed validation (decision must match evidence) | MEDIUM |
| `service.py` | `FutuNativeService`: polling loop, reconnect, backoff, health tracking | LOW |
| `__main__.py` | CLI entry, preflight checks, one-shot query | LOW |

## Key Functions

```
proxy.py:
  load_ip_pool()              → set[str]           # F3CLogin + CommonConfig.db
  extract_connip_ips(payload) → set[str]            # parse ConnIpRsp protobuf
  _ProxyBridge._connect_forward(ip) → socket        # route-lift: delete→connect→add
  _ProxyBridge._hot_add_route(ip) → bool            # add lo0 route for new IP
  _ProxyBridge._hot_add_login_redirect_ips(payload)  # parse LOGIN redirect protobuf, hot-add route
  _ProxyBridge._handle_connection(sock)              # bidirectional proxy with frame parsing + passthrough
  _ProxyBridge.intercept_login() → ProxySession|None # full lifecycle
  obtain_authenticated_session(config) → ProxySession|None  # top-level entry

protocol.py:
  build_header(cmd, body_len, seq, uid, ext) → bytes
  encode_varint(value) → bytes
  decode_varint(data, pos) → (value, new_pos)
  read_frame(sock) → Frame
  read_frame_for_command(sock, cmd, seq) → Frame    # skips heartbeats
  parse_quote_prices(frame, security_id) → (Decimal, Decimal)
  inspect_quote_response(frame, security_id) → tuple[QuoteSubtypeInspection, ...]
  build_quote_request(..., selectors=(...)) → bytes  # known read-only selectors only

adapter.py:
  ProxyQuoteClient(socket, user_id)
  ProxyQuoteClient.query(security_id) → (last, prev_close)
  resolve_jp_securities(paths) → (SecListResult, list[ResolvedSecurity])
```

## Constants

```python
PROXY_PORT = 19443
PF_ANCHOR = "stock-moni"
CMD_LOGIN = 0x1771
CMD_INIT = 0x1B0E
CMD_QUOTE = 0x1AA8
CMD_CONNIP = frozenset({0xFFE1, 0x0529, 0x4EB3})
HEADER_LENGTH = 32
MAX_BODY_LENGTH = 1024 * 1024
TARGET_SYMBOLS = ["1306", "1321", "1489"]
```

## Tests

28 tests total, all pure unit tests (no root, no network, no FTNN):
- `test_proxy.py` (8): route-lift mock, ConnIpRsp protobuf parsing, IP filtering, malformed input
- `test_futu_native_service.py` (11): service lifecycle, backoff, reconnect, health tracking
- `test_protocol_inspection.py` (9): sanitized shape inspection, malformed/missing fail-closed, uint64/group handling, selector allowlist

Phase A evidence and the complete capability matrix are under
`.codex-shared/evidence-market-fields/`. Only `last`/`prev_close` remain in the
production model; newly mapped fields are diagnostic evidence until a separate
Phase B contract is approved. `market_as_of`, NAV/iNAV, and premium-discount
remain unqualified and must not be inferred.

## Approaches That Failed (don't retry)

| Approach | Why it failed |
|----------|---------------|
| `IP_BOUND_IF` (setsockopt 25) | Conflicts with route traps → `EADDRNOTAVAIL` on all upstream connects |
| DNS hijack / /etc/hosts | FTNN doesn't use DNS for FT servers |
| SQLite modification | Cloud config overwrites on launch |
| Packet replay | Token consumed server-side, always rejected |
| lsof-only discovery | Too slow — TCP ESTABLISHED before route added |
| Two-phase kill/restart | Poor UX, race conditions |
| `_FrameStream` raise on non-FT data | Kills connection thread before sendall — breaks FTNN's TLS connections |
| Treat LOGIN result≠0 as final failure | FTNN uses result=1 as redirect — needs retry on redirect server |
| Regex IP extraction from LOGIN payload | Word boundary `\b` matches across protobuf field boundaries (e.g. "49.51.78.830") |

## stock-moni Integration

Production code at `stock-moni/src/stock_moni/observations/futu_native_app_session/`. Differences from this repo:
- `ProxyOutcome` / `ProxySetupError` typed error handling
- `_FrameStream` class (vs inline buffer parsing)
- State file v4 (mode-0600, owner identity, `cleanup_stale_state`)
- `run_command` injection for testability
- CLI: `uv run stock-moni futu-native-serve`
