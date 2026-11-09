#!/usr/bin/env python3
"""Lightweight inline IPS for an AWS Gateway Load Balancer (demo appliance).

Data path
  GWLB --GENEVE/UDP 6081--> this process --(inspect)--> same GENEVE packet back to the GWLB
                                          \\-(malicious)--> dropped (never returned)

* The GWLB wraps each customer packet (IP packet, protocol type 0x0800, or an
  Ethernet frame, 0x6558) in a GENEVE header. To let a packet continue, the
  appliance sends the *unchanged* GENEVE datagram back to the GWLB: outer IPs
  swapped, outer UDP ports PRESERVED (not swapped), TLVs/flow cookie intact.
  Not sending it back = the packet is dropped.
* Inspection: signature matching on the (URL-decoded) TCP payload.
* IPS behaviour: when a signature matches, the packet is dropped and the whole
  flow (5-tuple) is blocked for FLOW_BLOCK_SECONDS, so TCP retransmissions of the
  attack never get through either.
* TCP 8080: /health (GWLB health check) and /stats.
"""
import json
import os
import re
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_to_bytes

GENEVE_PORT = int(os.environ.get("GENEVE_PORT", "6081"))
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "8080"))
EVE_LOG = os.environ.get("EVE_LOG", "/var/log/gwlb-ips/eve.json")
FLOW_BLOCK_SECONDS = int(os.environ.get("FLOW_BLOCK_SECONDS", "120"))
RETURN_PORT = int(os.environ.get("GWLB_RETURN_PORT", "6081"))  # dst port of the reply (GWLB listens on 6081)
HOSTNAME = socket.gethostname()

I = re.IGNORECASE
SIGNATURES = [
    (1000001, "SQL injection - UNION SELECT", re.compile(rb"union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select", I)),
    (1000002, "SQL injection - tautology (' OR '1'='1)", re.compile(rb"('|\")\s*or\s*('|\")?\s*\w+('|\")?\s*=\s*('|\")?\s*\w+", I)),
    (1000003, "SQL injection - stacked/DROP TABLE", re.compile(rb";\s*(drop|delete|truncate)\s+(table|from)", I)),
    (1000010, "Path traversal / sensitive file access", re.compile(rb"(\.\./){2,}|/etc/(passwd|shadow)", I)),
    (1000020, "Cross-site scripting - <script>", re.compile(rb"<\s*script", I)),
    (1000030, "Log4Shell JNDI lookup", re.compile(rb"\$\{\s*jndi\s*:", I)),
    (1000040, "Shellshock", re.compile(rb"\(\)\s*\{\s*:\s*;\s*\}\s*;")),
    (1000050, "Remote command injection", re.compile(rb"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", I)),
    (1000060, "Vulnerability scanner user-agent", re.compile(rb"user-agent:[^\r\n]*(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|wpscan)", I)),
]
HTTP_REQ = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP/1\.[01]")

lock = threading.Lock()
stats = {"started": time.time(), "packets": 0, "forwarded": 0, "dropped": 0,
         "alerts": 0, "http_requests_allowed": 0, "non_ipv4": 0, "last_alerts": []}
blocked_flows = {}  # (src, sport, dst, dport) -> expiry


def eve(event):
    event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
    event["appliance"] = HOSTNAME
    try:
        with lock, open(EVE_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass


def parse_geneve(pkt):
    """Return (inner_ip_packet, vni) or None."""
    if len(pkt) < 8:
        return None
    b0, _flags, proto = struct.unpack("!BBH", pkt[:4])
    if b0 >> 6 != 0:  # version must be 0
        return None
    hdr = 8 + (b0 & 0x3F) * 4
    vni = int.from_bytes(pkt[4:7], "big")
    inner = pkt[hdr:]
    if proto == 0x6558:  # Transparent Ethernet bridging: strip the 14-byte Ethernet header
        if len(inner) < 14 or inner[12:14] != b"\x08\x00":
            return None
        inner = inner[14:]
    if not inner or inner[0] >> 4 != 4:
        return None
    return inner, vni


def parse_ipv4_tcp(ip):
    """Return (src, dst, proto, sport, dport, payload)."""
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:total]
    if proto in (6, 17) and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        if proto == 6 and len(l4) >= 20:
            off = (l4[12] >> 4) * 4
            return src, dst, proto, sport, dport, l4[off:]
        return src, dst, proto, sport, dport, l4[8:]
    return src, dst, proto, 0, 0, b""


def inspect(payload):
    """Return (sid, msg) of the first matching signature, else None."""
    decoded = unquote_to_bytes(payload.replace(b"+", b" ")) if b"%" in payload or b"+" in payload else payload
    for sid, msg, rx in SIGNATURES:
        if rx.search(payload) or rx.search(decoded):
            return sid, msg
    return None


_raw = None
_src_ip_cache = {}


def _udp_checksum(src, dst, udp):
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, len(udp))
    buf = pseudo + udp
    if len(buf) % 2:
        buf += b"\0"
    s = sum(struct.unpack("!%dH" % (len(buf) // 2), buf))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s & 0xFFFF) or 0xFFFF


def send_back(data, addr):
    """Return the GENEVE datagram to the GWLB.

    AWS requirement: swap the outer IP addresses but PRESERVE the outer UDP ports
    (i.e. src port = port the GWLB used, dst port = 6081). A normal UDP socket can't
    use an arbitrary source port, so the UDP header is built by hand on a raw socket.
    """
    global _raw
    if _raw is None:
        _raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    gwlb_ip, gwlb_port = addr
    src_ip = _src_ip_cache.get(gwlb_ip)
    if src_ip is None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((gwlb_ip, 9))
        src_ip = _src_ip_cache[gwlb_ip] = probe.getsockname()[0]
        probe.close()
    udp = struct.pack("!HHHH", gwlb_port, RETURN_PORT, 8 + len(data), 0) + data
    udp = udp[:6] + struct.pack("!H", _udp_checksum(src_ip, gwlb_ip, udp)) + udp[8:]
    _raw.sendto(udp, (gwlb_ip, 0))


def handle(sock, data, addr):
    stats["packets"] += 1
    parsed = parse_geneve(data)
    if not parsed:
        stats["non_ipv4"] += 1
        send_back(data, addr)  # not something we understand: fail-open
        stats["forwarded"] += 1
        return
    ip, vni = parsed
    src, dst, proto, sport, dport, payload = parse_ipv4_tcp(ip)
    flow = (src, sport, dst, dport)
    rflow = (dst, dport, src, sport)
    now = time.time()

    if blocked_flows.get(flow, 0) > now or blocked_flows.get(rflow, 0) > now:
        stats["dropped"] += 1
        return

    if proto == 6 and payload:
        hit = inspect(payload)
        if hit:
            sid, msg = hit
            line = HTTP_REQ.match(payload)
            blocked_flows[flow] = now + FLOW_BLOCK_SECONDS
            stats["alerts"] += 1
            stats["dropped"] += 1
            ev = {"event_type": "alert", "action": "blocked", "src_ip": src, "src_port": sport,
                  "dest_ip": dst, "dest_port": dport, "proto": "TCP", "vni": vni,
                  "signature_id": sid, "signature": msg,
                  "http_request": (line.group(0).decode("latin1")[:200] if line else payload[:120].decode("latin1"))}
            stats["last_alerts"] = (stats["last_alerts"] + [ev])[-20:]
            eve(ev)
            return
        line = HTTP_REQ.match(payload)
        if line:
            stats["http_requests_allowed"] += 1
            eve({"event_type": "http", "action": "allowed", "src_ip": src, "src_port": sport,
                 "dest_ip": dst, "dest_port": dport, "proto": "TCP", "vni": vni,
                 "http_request": line.group(0).decode("latin1")[:200]})

    send_back(data, addr)  # allowed: hand the packet back to the GWLB
    stats["forwarded"] += 1


class Health(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/stats"):
            body = json.dumps({**stats, "uptime": int(time.time() - stats["started"]),
                               "appliance": HOSTNAME}).encode()
        else:
            body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    os.makedirs(os.path.dirname(EVE_LOG), exist_ok=True)
    threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", HEALTH_PORT), Health).serve_forever,
                     daemon=True).start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", GENEVE_PORT))
    eve({"event_type": "start", "geneve_port": GENEVE_PORT})
    while True:
        data, addr = sock.recvfrom(65535)
        try:
            handle(sock, data, addr)
            if len(blocked_flows) > 5000:
                t = time.time()
                for k in [k for k, v in blocked_flows.items() if v < t]:
                    blocked_flows.pop(k, None)
        except Exception as exc:  # never crash the data path
            eve({"event_type": "error", "error": repr(exc)})
            try:
                send_back(data, addr)
            except OSError:
                pass


if __name__ == "__main__":
    main()
