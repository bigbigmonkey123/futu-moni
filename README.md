# futu-moni

Standalone market data client for [Futu/Moomoo](https://www.futunn.com) using the native FT protocol. No OpenD, no API key, no SDK required.

Connects directly to Futu quote servers via TCP + Protobuf on port 443, the same protocol the desktop app uses internally.

## Supported Markets

| Market | Route | Examples |
|--------|-------|---------|
| Hong Kong (HK) | 1 | 00700, 09988 |
| United States (US) | 11 | AAPL, NVDA, TSLA |
| Japan (JP) | 1001 | 1306, 1321, 1489 |

## Requirements

- Python 3.8+
- macOS (login capture uses `tcpdump`)
- Futu/Moomoo desktop app installed (for authentication and security database)
- No additional Python packages needed — stdlib only

## Quick Start

### 1. Capture a login packet

The client authenticates by replaying a login packet captured from your running Futu app session.

```bash
# Auto-capture: waits for the app to start, then captures
python futu_moni.py --auto-capture

# Manual capture: app must already be running
python futu_moni.py --capture-login
```

The captured packet is saved to `~/.futu-moni/login_replay.bin`. It expires when your app session ends — re-capture when needed.

### 2. Query any stock

```bash
# Query specific stocks across markets
python futu_moni.py --query 00700 AAPL 1306

# Output:
#   00700      Tencent Holdings Ltd.          HK       388.200      384.000  +1.09%
#   AAPL       Apple Inc                      US       198.110      196.890  +0.62%
#   1306       NEXT FUNDS TOPIX ETF           JP     2,781.000    2,770.000  +0.40%
```

### 3. Full JP market report

```bash
# Run with no arguments for a complete Japanese market overview
python futu_moni.py
```

This shows:
- Japanese indices (Nikkei 225, TOPIX, JPX-Nikkei 400)
- TOPIX-17 sector rankings (top/bottom movers)
- N225 constituent rankings (losers, turnover leaders)
- Target ETF prices

## Commands

| Command | Description |
|---------|-------------|
| *(no args)* | Full JP market report |
| `--query CODE1 CODE2 ...` | Query live prices for any stock codes |
| `--lookup CODE1 CODE2 ...` | Look up security IDs from local database |
| `--capture-login` | Capture login packet (app must be running) |
| `--auto-capture` | Wait for app to start, then auto-capture |
| `--check-login` | Verify if saved login packet is still valid |

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `FUTU_SERVER` | `49.51.78.83` | Override the default quote server IP |
| `FUTU_LOGIN_PACKET` | `~/.futu-moni/login_replay.bin` | Custom login packet path |

## How It Works

### Authentication

Futu's login uses RSA encryption with random padding — packets cannot be constructed from scratch. Instead, `futu-moni` captures a login packet from a live app session via `tcpdump` and replays it to authenticate with the quote server.

### Price Queries

Active price queries use CMD `0x1AA8` with selector 0, which returns current price and previous close in nanounits (÷10⁹). Each security is queried individually with market-specific routing.

### Security Lookup

Stock codes (like "00700" or "AAPL") are resolved to internal security IDs using Futu's local SQLite database (`SecListDB`), which is maintained by the desktop app. When a code exists in multiple markets (e.g., AAPL in US vs Canadian CDR), the preferred market is selected automatically.

### Protocol

The FT protocol uses a 32-byte big-endian header with magic bytes "FT", followed by a Protobuf-encoded body. Communication happens over plain TCP on port 443 (not TLS).

## Limitations

- **macOS only** — login capture depends on `tcpdump` and Futu's macOS app paths
- **Session-bound** — login packets expire when the app session ends
- **Read-only** — only fetches market data, no trading capability
- **Single security per request** — CMD 0x1AA8 returns only the first security in combined requests, so queries are sent one at a time

## License

MIT
