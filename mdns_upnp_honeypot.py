#!/usr/bin/env python3
"""
Hostile mDNS (5353) + UPnP (1900) responders for NSE broadcast scripts.
mDNS: answers multicast queries with crafted PTR/TXT/SRV records.
UPnP: replies to M-SEARCH with hostile LOCATION headers and giant XML.
"""
import socket
import struct
import threading
import time

def dns_name(labels):
    out = b""
    for l in labels:
        out += bytes([len(l)]) + l
    return out + b"\x00"

def mdns_record(rtype, name, rdata, ttl=120):
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata

def mdns_handler():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", 5353))
    except PermissionError:
        print("mdns bind failed", flush=True)
        return
    # join multicast group
    mreq = socket.inet_aton("224.0.0.251") + socket.inet_aton("0.0.0.0")
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    print("[*] hostile mDNS on :5353", flush=True)
    hostile_name = dns_name([b"hostile", b"local"])
    giant_txt = b"\xff" * 400  # TXT with hostile bytes
    ptr = b"\xc0\x0c"  # pointer
    while True:
        try:
            data, addr = s.recvfrom(4096)
            if len(data) < 12:
                continue
            txid = data[:2]
            # response: same txid, flags=0x8400 (auth answer), QDCOUNT echo
            qd = data[4:6]
            qsection = b""
            # echo the question section
            pos = 12
            try:
                # parse name length
                while pos < len(data) and data[pos] != 0:
                    if data[pos] & 0xC0 == 0xC0:
                        pos += 2
                        break
                    pos += 1 + data[pos]
                pos += 1  # null
                qsection = data[12:pos + 4]
                qd = struct.pack(">H", 1)
            except Exception:
                pass
            answers = (
                mdns_record(12, b"\xc0\x0c", hostile_name) +       # PTR
                mdns_record(16, b"\xc0\x0c", giant_txt) +          # TXT (hostile)
                mdns_record(33, b"\xc0\x0c", struct.pack(">HHIH", 0, 0, 8080, 4, socket.inet_aton("127.0.0.1"))) +  # SRV
                mdns_record(1, hostile_name, socket.inet_aton("127.0.0.1"))  # A
            )
            resp = txid + struct.pack(">HHHHH", 0x8400, 1, 4, 0, 0) + qsection + answers
            s.sendto(resp, addr)
        except OSError:
            return

def upnp_handler():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", 1900))
    except PermissionError:
        print("upnp bind failed", flush=True)
        return
    mreq = socket.inet_aton("239.255.255.250") + socket.inet_aton("0.0.0.0")
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    print("[*] hostile UPnP on :1900", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
            if b"M-SEARCH" in data or b"NOTIFY" in data or True:
                # hostile LOCATION + SERVER + USN with control chars and giant values
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"CACHE-CONTROL: max-age=1800\r\n"
                    b"LOCATION: http://192.168.88.8:8899/desc.xml\x1b]2;PWNED\x07\r\n"
                    b"SERVER: " + b"U" * 900 + b"\r\n"
                    b"ST: upnp:rootdevice\r\n"
                    b"USN: uuid:" + b"\xff\xfe" * 100 + b"::upnp:rootdevice\r\n"
                    b"EXT:\r\n\r\n"
                )
                s.sendto(resp, addr)
        except OSError:
            return

def main():
    t1 = threading.Thread(target=mdns_handler, daemon=True)
    t2 = threading.Thread(target=upnp_handler, daemon=True)
    t1.start(); t2.start()
    while True:
        time.sleep(3600)

if __name__ == "__main__":
    main()
