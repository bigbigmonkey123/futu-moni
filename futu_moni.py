#!/usr/bin/env python3
"""
futu-moni — Standalone market data client for Futu/Moomoo.

Connects directly to Futu quote servers via the native FT protocol
(TCP + Protobuf over port 443). No OpenD, no API key, no SDK required.

Supported markets:
  HK  — Hong Kong stocks      (route 1)
  US  — US stocks              (route 11)
  JP  — Japanese stocks/ETFs   (route 1001)
  SH  — Shanghai A-shares      (route TBD)
  SZ  — Shenzhen A-shares      (route TBD)

Authentication: captures a login packet from a running Futu desktop app
session via tcpdump, then replays it for server authentication.

Usage:
  futu_moni.py                          # Full JP market report
  futu_moni.py --query 00700 AAPL 1306  # Query any stock by code
  futu_moni.py --capture-login          # Capture login (app must be running)
  futu_moni.py --auto-capture           # Wait for app, then capture
"""

import struct
import socket
import time
import sqlite3
import sys
import os
import select
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PROTOCOL_VER = 10095
CMD_LOGIN = 0x1771
CMD_SUBSCRIBE = 0x19C9
CMD_INIT = 0x1B0E
CMD_PUSH = 0x1844
CMD_QUOTE = 0x1AA8

MAIN_SERVER = os.environ.get("FUTU_SERVER", "49.51.78.83")
LOGIN_PACKET_PATH = os.environ.get(
    "FUTU_LOGIN_PACKET",
    os.path.expanduser("~/.futu-moni/login_replay.bin"),
)

PRIMARY_SERVERS = [
    "119.29.48.17", "119.29.43.101", "119.28.37.77",
    "119.28.37.206", "106.55.67.68", "124.156.124.214",
]

JST = timezone(timedelta(hours=9))

# ---------------------------------------------------------------------------
# Market data — security IDs and routes
# ---------------------------------------------------------------------------

INDICES = {
    82669546513412: (".N225", "Nikkei 225", 2),
    82669546513437: (".TOPIX", "TOPIX", 2),
    82669546513410: (".JPXN400", "JPX-Nikkei 400", 2),
}

TOPIX17_SECTORS = {
    82669546513420: (".T17ATE", "Autos & Transport Equip"),
    82669546513421: (".T17B", "Banks"),
    82669546513422: (".T17CM", "Construction & Materials"),
    82669546513423: (".T17CWT", "Commercial & Wholesale"),
    82669546513424: (".T17EAPI", "Electric App & Precision"),
    82669546513425: (".T17EPG", "Electric Power & Gas"),
    82669546513426: (".T17ER", "Energy Resources"),
    82669546513427: (".T17FD", "Foods"),
    82669546513428: (".T17FIN", "Financials ex Banks"),
    82669546513429: (".T17ISO", "IT & Services & Others"),
    82669546513430: (".T17M", "Machinery"),
    82669546513431: (".T17PHR", "Pharmaceutical"),
    82669546513432: (".T17RE", "Real Estate"),
    82669546513433: (".T17RMC", "Raw Materials & Chemicals"),
    82669546513434: (".T17RT", "Retail Trade"),
    82669546513435: (".T17SNM", "Steel & Nonferrous Metals"),
    82669546513436: (".T17TL", "Transport & Logistics"),
}

ETF_TARGETS = {
    82669546513451: ("1306", "NEXT FUNDS TOPIX ETF", 1),
    82669546513459: ("1321", "NEXT FUNDS Nikkei 225 ETF", 1),
    82669546513559: ("1489", "NF Nikkei High Div 50 ETF", 1),
}

MARKET_ROUTES = {
    1: 1,       # HK → route 1
    11: 11,     # US → route 11
    830: 1001,  # JP → route 1001
}

PREFERRED_MARKETS = [1, 11, 21, 22, 830]

# Futu app's local security database (SQLite)
SECLIST_DB_PATHS = [
    os.path.expanduser("~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v13.dat"),
    os.path.expanduser("~/.com.futunn.FutuOpenD/F3CNN/SecListDB.v12.dat"),
]

# ---------------------------------------------------------------------------
# Protobuf varint helpers
# ---------------------------------------------------------------------------


def encode_varint(value):
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


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


# ---------------------------------------------------------------------------
# FT protocol helpers
# ---------------------------------------------------------------------------


def _extract_user_id(login_packet):
    """Extract user ID from a captured login packet's FT header."""
    if not login_packet or len(login_packet) < 32:
        return 0
    raw = struct.unpack('>I', login_packet[8:12])[0]
    return raw >> 8


def build_header(cmd, body_len, seq=0, user_id=0):
    header = bytearray(32)
    header[0:2] = b'FT'
    struct.pack_into('>H', header, 2, PROTOCOL_VER)
    struct.pack_into('>I', header, 8, user_id << 8)
    struct.pack_into('>I', header, 12, seq)
    struct.pack_into('>H', header, 16, cmd)
    struct.pack_into('>I', header, 18, body_len)
    header[31] = 0x2c
    return bytes(header)


def build_subscribe(security_id, market=101, sub_type=2):
    auth_inner = (b'\x0a\x10' + b'\x00' * 16
                  + b'\x12\x08' + b'\x00' * 8
                  + b'\x1a\x08' + b'\x00' * 8)
    auth_block = b'\x0a' + encode_varint(len(auth_inner)) + auth_inner
    short_f4 = b'\x22\x02\x08\x00'
    payload = b''
    payload += b'\x08' + encode_varint(security_id)
    payload += b'\x10' + encode_varint(sub_type)
    payload += b'\x18' + encode_varint(market)
    payload += b'\x20\x00\x28\x30'
    payload += b'\x70' + encode_varint(1001)
    payload += b'\x88\x01' + encode_varint(1001)
    payload += b'\x88\x01' + encode_varint(1007)
    payload += b'\xb0\x01\x01\xb8\x01' + encode_varint(1001)
    payload += b'\xc0\x01' + encode_varint(1001)
    payload += b'\xc0\x01' + encode_varint(1007)
    return auth_block + short_f4 + payload


def recv_full(sock, timeout=10):
    data = b''
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) >= 32:
                blen = struct.unpack('>I', data[18:22])[0]
                if len(data) >= 32 + blen:
                    break
    except socket.timeout:
        pass
    return data


def extract_tail_prices(rbody):
    if len(rbody) < 20:
        return None, None
    search_region = rbody[-60:]
    best = (None, None)
    for i in range(len(search_region) - 2):
        if search_region[i] != 0x40:
            continue
        try:
            f8_val, next_pos = decode_varint(search_region, i + 1)
            if f8_val < 1000 or f8_val > 10_000_000_000:
                continue
            if next_pos < len(search_region) and search_region[next_pos] == 0x48:
                f9_val, _ = decode_varint(search_region, next_pos + 1)
                if f9_val < 1000 or f9_val > 10_000_000_000:
                    continue
                best = (f8_val, f9_val)
        except Exception:
            continue
    return best


def parse_constituents(rbody):
    entries = []
    pos = 8
    while pos < len(rbody):
        try:
            tag, npos = decode_varint(rbody, pos)
            fn = tag >> 3
            wt = tag & 7
            if fn == 0 or fn > 500:
                pos += 1
                continue
            if wt == 0:
                _, npos = decode_varint(rbody, npos)
                pos = npos
            elif wt == 2:
                length, npos = decode_varint(rbody, npos)
                if npos + length > len(rbody):
                    break
                if fn == 4 and length > 20:
                    entry = rbody[npos:npos + length]
                    fields = {}
                    epos = 0
                    while epos < len(entry):
                        try:
                            etag, enpos = decode_varint(entry, epos)
                            efn = etag >> 3
                            ewt = etag & 7
                            if efn == 0 or efn > 500:
                                epos += 1
                                continue
                            if ewt == 0:
                                eval_, enpos = decode_varint(entry, enpos)
                                fields[efn] = eval_
                                epos = enpos
                            elif ewt == 2:
                                el, enpos = decode_varint(entry, enpos)
                                epos = enpos + el
                            elif ewt == 1:
                                epos = enpos + 8
                            elif ewt == 5:
                                epos = enpos + 4
                            else:
                                epos += 1
                        except Exception:
                            break
                    if 1 in fields and fields.get(2, 0) > 0:
                        entries.append(fields)
                pos = npos + length
            elif wt == 1:
                pos = npos + 8
            elif wt == 5:
                pos = npos + 4
            else:
                pos += 1
        except Exception:
            break
    return entries


# ---------------------------------------------------------------------------
# FTNNClient — basic subscription-based data (indices, sectors, rankings)
# ---------------------------------------------------------------------------


class FTNNClient:
    def __init__(self):
        self.sock = None
        self.seq = 0
        self.user_id = 0

    def connect(self):
        if os.path.exists(LOGIN_PACKET_PATH):
            with open(LOGIN_PACKET_PATH, 'rb') as f:
                login_pkt = f.read()
            self.user_id = _extract_user_id(login_pkt)
            if self._try_login(MAIN_SERVER, login_pkt, is_raw_packet=True):
                return MAIN_SERVER
        for ip in [MAIN_SERVER] + PRIMARY_SERVERS:
            if self._try_connect(ip):
                return ip
        return None

    def _try_connect(self, ip):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((ip, 443))
            return True
        except Exception:
            return False

    def _try_login(self, ip, login_data, is_raw_packet=False):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((ip, 443))
            if is_raw_packet:
                self.sock.sendall(login_data)
            else:
                hdr = build_header(CMD_LOGIN, len(login_data), 0, self.user_id)
                self.sock.sendall(hdr + login_data)
            data = recv_full(self.sock)
            if data and len(data) >= 32:
                exhl = struct.unpack('>H', data[30:32])[0]
                blen = struct.unpack('>I', data[18:22])[0]
                rbody = data[32 + exhl:32 + blen]
                pos = 0
                result = None
                while pos < len(rbody):
                    try:
                        tag, npos = decode_varint(rbody, pos)
                        fn = tag >> 3
                        wt = tag & 7
                        if wt == 0:
                            val, npos = decode_varint(rbody, npos)
                            if fn == 1:
                                result = val
                            pos = npos
                        elif wt == 2:
                            l, npos = decode_varint(rbody, npos)
                            pos = npos + l
                        elif wt == 1:
                            pos = npos + 8
                        elif wt == 5:
                            pos = npos + 4
                        else:
                            pos += 1
                    except Exception:
                        break
                if result == 0:
                    self.seq = 302 if is_raw_packet else 1
                    return True
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        return False

    def subscribe(self, security_id, market=101, sub_type=2):
        self.seq += 1
        body = build_subscribe(security_id, market, sub_type)
        hdr = build_header(CMD_SUBSCRIBE, len(body), self.seq, self.user_id)
        self.sock.sendall(hdr + body)
        time.sleep(0.3)
        data = recv_full(self.sock, timeout=5)
        if data and len(data) > 32:
            blen = struct.unpack('>I', data[18:22])[0]
            return data[32:32 + blen]
        return b''

    def fetch_indices(self):
        results = {}
        for sid, (symbol, name, pa) in INDICES.items():
            rbody = self.subscribe(sid)
            if len(rbody) > 30:
                last_raw, prev_raw = extract_tail_prices(rbody)
                if last_raw:
                    results[symbol] = {
                        'name': name,
                        'last': last_raw / 1000,
                        'prev': prev_raw / 1000 if prev_raw else 0,
                    }
        return results

    def fetch_sectors(self):
        results = {}
        for sid, (symbol, name) in TOPIX17_SECTORS.items():
            rbody = self.subscribe(sid)
            if len(rbody) > 30:
                last_raw, prev_raw = extract_tail_prices(rbody)
                if last_raw:
                    last = last_raw / 1000
                    prev = prev_raw / 1000 if prev_raw else 0
                    chg_pct = ((last - prev) / prev * 100) if prev > 0 else 0
                    results[symbol] = {
                        'name': name, 'last': last,
                        'prev': prev, 'chg_pct': chg_pct,
                    }
        return results

    def fetch_rankings(self):
        seen = set()
        stocks = []
        for sid, st in [(82669546513412, 1), (10007910, 1), (10191334, 1)]:
            rbody = self.subscribe(sid, sub_type=st)
            for fields in parse_constituents(rbody):
                stock_id = fields.get(1, 0)
                if stock_id < 1000 or stock_id in seen:
                    continue
                seen.add(stock_id)
                last = fields.get(2, 0) / 1000
                prev = fields.get(9, 0) / 1000
                vol = fields.get(5, 0)
                turnover = fields.get(4, 0)
                if last == 0 or prev == 0:
                    continue
                chg_pct = ((last - prev) / prev * 100) if prev > 0 else 0
                code = str(stock_id)
                stocks.append({
                    'code': code, 'name': code, 'last': last,
                    'prev': prev, 'chg_pct': chg_pct, 'vol': vol,
                    'turnover': turnover,
                })
        return stocks

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# AuthenticatedQuoteClient — login-replay based, supports active price query
# ---------------------------------------------------------------------------


class AuthenticatedQuoteClient:
    def __init__(self, login_packet_path=LOGIN_PACKET_PATH):
        self.sock = None
        self.seq = 301
        self.login_packet = None
        self.user_id = 0
        if os.path.exists(login_packet_path):
            with open(login_packet_path, 'rb') as f:
                self.login_packet = f.read()
            self.user_id = _extract_user_id(self.login_packet)

    def _build_header(self, cmd, body_len, seq, ex_head_len=44):
        h = bytearray(32)
        h[0:2] = b'FT'
        h[2] = 0x27
        h[3] = 0x6F
        struct.pack_into('>H', h, 4, 0x41A8)
        struct.pack_into('>H', h, 6, 0x0200)
        struct.pack_into('>I', h, 8, self.user_id << 8)
        struct.pack_into('>I', h, 12, seq)
        struct.pack_into('>H', h, 16, cmd)
        struct.pack_into('>I', h, 18, body_len)
        struct.pack_into('>H', h, 30, ex_head_len)
        return bytes(h)

    def _make_extend_head(self):
        trace_id = os.urandom(16)
        span_id = os.urandom(8)
        parent_span = os.urandom(8)
        trace_info = (b'\x0a\x10' + trace_id + b'\x12\x08' + span_id
                      + b'\x1a\x08' + parent_span)
        return b'\x0a' + encode_varint(len(trace_info)) + trace_info + b'\x22\x02\x08\x00'

    def _recv_msg(self, timeout=5):
        self.sock.settimeout(timeout)
        resp = b''
        try:
            while len(resp) < 32:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                resp += chunk
            if resp[:2] != b'FT':
                return None
            blen = struct.unpack('>I', resp[18:22])[0]
            while len(resp) < 32 + blen:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            return resp
        except socket.timeout:
            return resp if len(resp) >= 32 else None

    def connect_and_login(self):
        if not self.login_packet:
            return False
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((MAIN_SERVER, 443))
            self.sock.sendall(self.login_packet)
            resp = self._recv_msg()
            if not resp:
                return False
            exhl = struct.unpack('>H', resp[30:32])[0]
            blen = struct.unpack('>I', resp[18:22])[0]
            payload = resp[32 + exhl:32 + blen]
            if len(payload) < 2:
                return False
            _, p = decode_varint(payload, 0)
            ret_code, _ = decode_varint(payload, p)
            if ret_code != 0:
                return False
            self.seq = 302
            eh = self._make_extend_head()
            init_payload = bytes.fromhex('0807101118012000281e3a020800')
            body = eh + init_payload
            hdr = self._build_header(CMD_INIT, len(body), self.seq, len(eh))
            self.sock.sendall(hdr + body)
            self.seq += 1
            self._recv_msg(timeout=3)
            return True
        except Exception:
            return False

    def query_prices(self, securities):
        """Query live prices for arbitrary securities.

        Args:
            securities: list of (sec_id, code, name, market_code) tuples.

        Returns:
            dict of {code: {name, last, prev, chg_pct}}.
        """
        results = {}
        for sec_id, code, name, market_code in securities:
            route = MARKET_ROUTES.get(market_code, 1)
            inner = b'\x08' + encode_varint(sec_id)
            for s in [0, 1, 2]:
                sel_body = b'\x08' + encode_varint(s)
                inner += b'\x12' + encode_varint(len(sel_body)) + sel_body
            inner += b'\x18' + encode_varint(route)
            items = b'\x0a' + encode_varint(len(inner)) + inner
            eh = self._make_extend_head()
            body = eh + items
            hdr = self._build_header(CMD_QUOTE, len(body), self.seq, len(eh))
            self.sock.sendall(hdr + body)
            self.seq += 1
            resp = self._recv_msg(timeout=5)
            if not resp or len(resp) < 32:
                continue
            exhl = struct.unpack('>H', resp[30:32])[0]
            blen = struct.unpack('>I', resp[18:22])[0]
            rbody = resp[32 + exhl:32 + blen]
            marker = b'\x08' + encode_varint(sec_id)
            idx = rbody.find(marker)
            if idx < 0:
                continue
            item_start = idx
            for s in range(idx, max(0, idx - 10), -1):
                if rbody[s] == 0x0a:
                    item_start = s
                    break
            try:
                pos = item_start
                _, pos = decode_varint(rbody, pos)
                item_len, pos = decode_varint(rbody, pos)
                item_data = rbody[pos:pos + item_len]
                price = self._extract_type0_price(item_data)
                if price:
                    cur, prev = price
                    chg_pct = ((cur - prev) / prev * 100) if prev > 0 else 0
                    results[code] = {
                        'name': name, 'last': cur,
                        'prev': prev, 'chg_pct': chg_pct,
                    }
            except Exception:
                pass
            time.sleep(0.2)
        return results

    def fetch_etf_prices(self):
        secs = [(sid, code, name, 830)
                for sid, (code, name, _) in ETF_TARGETS.items()]
        return self.query_prices(secs)

    def _extract_type0_price(self, item_data):
        ipos = 0
        while ipos < len(item_data):
            try:
                itag, inp = decode_varint(item_data, ipos)
            except Exception:
                break
            ifn = itag >> 3
            iwt = itag & 7
            if iwt == 0:
                _, inp = decode_varint(item_data, inp)
                ipos = inp
            elif iwt == 2:
                il, inp = decode_varint(item_data, inp)
                sub = item_data[inp:inp + il]
                ipos = inp + il
                if ifn == 2 and il > 10:
                    sp = 0
                    stype = -1
                    sdata = None
                    while sp < len(sub):
                        try:
                            st, snp = decode_varint(sub, sp)
                        except Exception:
                            break
                        sfn = st >> 3
                        swt = st & 7
                        if swt == 0:
                            sv, snp = decode_varint(sub, snp)
                            if sfn == 1:
                                stype = sv
                            sp = snp
                        elif swt == 2:
                            sl, snp = decode_varint(sub, snp)
                            if sfn == 2:
                                sdata = sub[snp:snp + sl]
                            sp = snp + sl
                        else:
                            break
                    if stype == 0 and sdata:
                        dp = 0
                        fields = {}
                        while dp < len(sdata):
                            try:
                                dt, dnp = decode_varint(sdata, dp)
                            except Exception:
                                break
                            dfn = dt >> 3
                            dwt = dt & 7
                            if dwt == 0:
                                dv, dnp = decode_varint(sdata, dnp)
                                fields[dfn] = dv
                                dp = dnp
                            else:
                                break
                        if 1 in fields:
                            return (fields[1] / 1e9, fields.get(2, 0) / 1e9)
            else:
                break
        return None

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Security lookup from Futu's local SecListDB
# ---------------------------------------------------------------------------


def _find_seclist_db():
    for p in SECLIST_DB_PATHS:
        if os.path.exists(p):
            return p
    return None


def lookup_securities(codes):
    """Look up security IDs from the Futu SecListDB (SQLite).

    Deduplicates by code, preferring main markets (HK > US > SH > SZ > JP).
    """
    db_path = _find_seclist_db()
    if not db_path:
        return []
    placeholders = ','.join('?' for _ in codes)
    try:
        conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        rows = conn.execute(
            f"SELECT id, code, name_en, market_code FROM security "
            f"WHERE code IN ({placeholders}) AND delete_flag=0 AND delisted=0 "
            f"ORDER BY market_code",
            codes
        ).fetchall()
        conn.close()
    except Exception:
        return []
    best = {}
    for sid, code, name, mkt in rows:
        if code not in best:
            best[code] = (sid, code, name, mkt)
        elif mkt in PREFERRED_MARKETS and best[code][3] not in PREFERRED_MARKETS:
            best[code] = (sid, code, name, mkt)
        elif (mkt in PREFERRED_MARKETS and best[code][3] in PREFERRED_MARKETS
              and PREFERRED_MARKETS.index(mkt) < PREFERRED_MARKETS.index(best[code][3])):
            best[code] = (sid, code, name, mkt)
    return list(best.values())


# ---------------------------------------------------------------------------
# Login packet capture
# ---------------------------------------------------------------------------


def capture_login_packet(output_path=LOGIN_PACKET_PATH, duration=30):
    """Capture a login packet from live Futu app traffic via tcpdump."""
    import subprocess
    import tempfile

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pcap_path = tempfile.mktemp(suffix='.pcap')
    print(f"Capturing Futu traffic for {duration}s...")
    print("If the app is already running, restart it to trigger a fresh login.")
    try:
        subprocess.run(
            ['sudo', 'tcpdump', '-i', 'any', f'host {MAIN_SERVER}',
             '-w', pcap_path, '-c', '500'],
            timeout=duration, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    if not os.path.exists(pcap_path):
        print("ERROR: No capture file created.")
        return False
    with open(pcap_path, 'rb') as f:
        raw = f.read()
    os.unlink(pcap_path)
    pos = 0
    while pos + 12 <= len(raw):
        block_type = struct.unpack('<I', raw[pos:pos + 4])[0]
        block_len = struct.unpack('<I', raw[pos + 4:pos + 8])[0]
        if block_len < 12 or block_len > 10000000:
            break
        if block_type == 0x00000006:
            cap_len = struct.unpack('<I', raw[pos + 20:pos + 24])[0]
            frame = raw[pos + 28:pos + 28 + cap_len]
            for offset in range(0, min(len(frame), 200)):
                if (offset + 20 <= len(frame)
                        and (frame[offset] & 0xF0) == 0x40):
                    ip_proto = frame[offset + 9]
                    dst_ip = '.'.join(str(b)
                                      for b in frame[offset + 16:offset + 20])
                    if ip_proto == 6 and dst_ip == MAIN_SERVER:
                        ip_hdr_len = (frame[offset] & 0x0F) * 4
                        tcp_start = offset + ip_hdr_len
                        tcp_hdr_len = ((frame[tcp_start + 12] >> 4) & 0xF) * 4
                        ip_total = struct.unpack(
                            '>H', frame[offset + 2:offset + 4])[0]
                        tcp_payload = frame[tcp_start + tcp_hdr_len:
                                            offset + ip_total]
                        if (len(tcp_payload) >= 32
                                and tcp_payload[:2] == b'FT'):
                            cmd = struct.unpack('>H', tcp_payload[16:18])[0]
                            if cmd == CMD_LOGIN:
                                blen = struct.unpack(
                                    '>I', tcp_payload[18:22])[0]
                                pkt = tcp_payload[:32 + blen]
                                with open(output_path, 'wb') as out:
                                    out.write(pkt)
                                uid = _extract_user_id(pkt)
                                print(f"Login packet saved: {len(pkt)}B "
                                      f"(user {uid}) -> {output_path}")
                                return True
        pos += block_len
    print("ERROR: No login packet found in capture.")
    return False


def auto_capture_login():
    """Wait for the Futu app to start, then capture its login packet."""
    import subprocess
    print("Auto-capture: waiting for Futu app to start...")
    print("  Launch the Futu/Moomoo desktop app now.")
    print("  Press Ctrl+C to cancel.\n")
    while True:
        for proc_name in ['富途牛牛', 'Moomoo', 'FutuBull']:
            result = subprocess.run(['pgrep', '-x', proc_name],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                pid = result.stdout.strip().split('\n')[0]
                print(f"  App detected ({proc_name}, PID {pid}), "
                      f"starting capture...")
                time.sleep(1)
                if capture_login_packet(duration=60):
                    ac = AuthenticatedQuoteClient()
                    if ac.connect_and_login():
                        print("  Login packet verified OK.")
                        ac.close()
                        return True
                    else:
                        print("  Warning: captured but verification failed.")
                        ac.close()
                return False
        time.sleep(2)


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------


def print_header(title):
    w = 70
    print(f"\n{'=' * w}")
    print(f"  {title}")
    print(f"{'=' * w}")


def main():
    now_jst = datetime.now(JST)
    print(f"\n  futu-moni — Market Data Client")
    print(f"  {now_jst.strftime('%Y-%m-%d %H:%M:%S')} JST")

    market_open = 9 <= now_jst.hour < 15 and now_jst.weekday() < 5
    if not market_open:
        print(f"  Note: Tokyo market is CLOSED. Data shows last session.")

    client = FTNNClient()
    server = client.connect()
    if not server:
        print("ERROR: Could not connect to any server.")
        print("  Run --capture-login first to authenticate.")
        sys.exit(1)
    print(f"  Connected to {server}")

    # [A] Japanese Indices
    print_header("[A] JAPANESE INDICES")
    indices = client.fetch_indices()
    if indices:
        print(f"  {'Index':<20s} {'Last':>12s} {'Prev Close':>12s} "
              f"{'Change':>10s}")
        print(f"  {'-' * 56}")
        for symbol, d in indices.items():
            chg = d['last'] - d['prev'] if d['prev'] > 0 else 0
            chg_pct = (chg / d['prev'] * 100) if d['prev'] > 0 else 0
            sign = '+' if chg >= 0 else ''
            print(f"  {d['name']:<20s} {d['last']:>12,.2f} "
                  f"{d['prev']:>12,.2f} {sign}{chg_pct:.2f}%")
    else:
        print("  No index data available.")

    # [D] Sector Rankings (TOPIX-17)
    print_header("[D] SECTOR RANKINGS (TOPIX-17)")
    sectors = client.fetch_sectors()
    if sectors:
        sorted_sectors = sorted(sectors.values(),
                                key=lambda x: x['chg_pct'], reverse=True)
        for label, items in [("Top 5 Gainers", sorted_sectors[:5]),
                             ("Top 5 Losers", sorted_sectors[-5:][::-1])]:
            print(f"\n  {label}:")
            print(f"  {'Sector':<28s} {'Last':>10s} {'Change':>10s}")
            print(f"  {'-' * 50}")
            for d in items:
                sign = '+' if d['chg_pct'] >= 0 else ''
                print(f"  {d['name']:<28s} {d['last']:>10,.2f} "
                      f"{sign}{d['chg_pct']:.2f}%")
    else:
        print("  No sector data available.")

    # [B] Market Rankings
    print_header("[B] MARKET RANKINGS (N225 Constituents)")
    stocks = client.fetch_rankings()
    if stocks:
        losers = sorted([s for s in stocks if s['chg_pct'] < 0],
                        key=lambda x: x['chg_pct'])
        by_turnover = sorted([s for s in stocks if s['turnover'] > 0],
                             key=lambda x: x['turnover'], reverse=True)[:10]
        for label, items, show_vol in [("Top Losers", losers[:10], False),
                                       ("Top by Turnover", by_turnover, True)]:
            if not items:
                continue
            print(f"\n  {label}:")
            if show_vol:
                print(f"  {'Code':<8s} {'Name':<25s} {'Last':>10s} "
                      f"{'Volume':>14s}")
                print(f"  {'-' * 60}")
                for s in items:
                    print(f"  {s['code']:<8s} {s['name']:<25s} "
                          f"¥{s['last']:>9,.1f} {s['vol']:>14,}")
            else:
                print(f"  {'Code':<8s} {'Name':<25s} {'Last':>10s} "
                      f"{'Change':>10s}")
                print(f"  {'-' * 55}")
                for s in items:
                    sign = '+' if s['chg_pct'] >= 0 else ''
                    print(f"  {s['code']:<8s} {s['name']:<25s} "
                          f"¥{s['last']:>9,.1f} {sign}{s['chg_pct']:.2f}%")
        print(f"\n  ({len(stocks)} stocks with live data"
              f"{' — more during market hours' if not market_open else ''})")
    else:
        print("  No ranking data available (market may be closed).")

    # [C] ETFs
    print_header("[C] TARGET ETFs")
    etfs = {}
    auth_client = AuthenticatedQuoteClient()
    if auth_client.login_packet and auth_client.connect_and_login():
        etfs = auth_client.fetch_etf_prices()
        auth_client.close()
    if etfs:
        print(f"  {'Code':<8s} {'Name':<30s} {'Last':>10s} "
              f"{'Prev':>10s} {'Change':>10s}")
        print(f"  {'-' * 72}")
        for code, d in sorted(etfs.items()):
            sign = '+' if d.get('chg_pct', 0) >= 0 else ''
            prev_str = (f"¥{d['prev']:>9,.1f}" if d.get('prev') else '')
            print(f"  {code:<8s} {d['name']:<30s} ¥{d['last']:>9,.1f} "
                  f"{prev_str} {sign}{d.get('chg_pct', 0):.2f}%")
    else:
        print("  No ETF data available.", end="")
        if not os.path.exists(LOGIN_PACKET_PATH):
            print(" Run --capture-login first.")
        else:
            print(" Login packet may be expired — re-run --capture-login.")

    print(f"\n{'=' * 70}")
    client.close()


def query_stocks(codes):
    """Query prices for arbitrary stock codes."""
    secs = lookup_securities(codes)
    if not secs:
        print(f"No securities found for: {', '.join(codes)}")
        db = _find_seclist_db()
        if not db:
            print("  SecListDB not found. Is Futu/Moomoo installed?")
        return
    print(f"\n  Querying {len(secs)} securities...")
    ac = AuthenticatedQuoteClient()
    if not (ac.login_packet and ac.connect_and_login()):
        print("  ERROR: Login failed. "
              "Run --capture-login or --auto-capture first.")
        return
    results = ac.query_prices(secs)
    ac.close()
    if results:
        market_names = {1: 'HK', 11: 'US', 21: 'SH', 22: 'SZ', 830: 'JP'}
        print(f"\n  {'Code':<10s} {'Name':<30s} {'Mkt':<4s} "
              f"{'Last':>12s} {'Prev':>12s} {'Chg':>8s}")
        print(f"  {'-' * 80}")
        sec_map = {s[1]: s[3] for s in secs}
        for code, d in sorted(results.items()):
            mkt = market_names.get(sec_map.get(code, 0), '?')
            sign = '+' if d['chg_pct'] >= 0 else ''
            print(f"  {code:<10s} {d['name']:<30s} {mkt:<4s} "
                  f"{d['last']:>12,.3f} {d['prev']:>12,.3f} "
                  f"{sign}{d['chg_pct']:.2f}%")
    else:
        print("  No price data returned.")
    not_found = [c for c in codes if c not in results]
    if not_found:
        print(f"  Missing: {', '.join(not_found)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == '--capture-login':
            capture_login_packet()
        elif cmd == '--auto-capture':
            auto_capture_login()
        elif cmd == '--check-login':
            if os.path.exists(LOGIN_PACKET_PATH):
                ac = AuthenticatedQuoteClient()
                ok = ac.connect_and_login()
                print(f"Login packet: {'valid' if ok else 'expired/invalid'}")
                if ok:
                    print(f"  User ID: {ac.user_id}")
                ac.close()
            else:
                print(f"No login packet at {LOGIN_PACKET_PATH}")
        elif cmd == '--query':
            if len(sys.argv) < 3:
                print("Usage: --query CODE1 CODE2 ...")
                print("  e.g.: --query 00700 AAPL 1306 NVDA 09988")
            else:
                query_stocks(sys.argv[2:])
        elif cmd == '--lookup':
            if len(sys.argv) < 3:
                print("Usage: --lookup CODE1 CODE2 ...")
            else:
                secs = lookup_securities(sys.argv[2:])
                if secs:
                    for sid, code, name, mkt in secs:
                        print(f"  {code:<10s} {name:<40s} "
                              f"market={mkt} secId={sid}")
                else:
                    print("  No securities found.")
        else:
            print(f"Usage: {sys.argv[0]} [OPTIONS]")
            print()
            print("  (no args)          Full JP market report")
            print("  --query CODES      Query prices for specific stocks")
            print("  --lookup CODES     Look up security IDs from local DB")
            print("  --capture-login    Capture login packet (app must run)")
            print("  --auto-capture     Wait for app start, then capture")
            print("  --check-login      Verify saved login packet")
            print()
            print("Environment variables:")
            print("  FUTU_SERVER        Override default server IP")
            print("  FUTU_LOGIN_PACKET  Override login packet path")
    else:
        main()
