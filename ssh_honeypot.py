#!/usr/bin/env python3
"""
Hostile SSH responder: speaks just enough SSH to feed nmap's libssh2-based
scripts (ssh-hostkey, ssh2-enum-algos) attacker-crafted KEX data.

Sends:
  1. A hostile version banner (control chars, long)
  2. SSH_MSG_KEXINIT with hostile algorithm name lists:
     - very long algorithm names
     - huge list counts
     - UTF-8/8-bit junk in names
     - empty algorithm fields
  3. Optionally answers KEXDH_INIT with a crafted reply (host key blob
     and signature are fully attacker-controlled bytes).

Then optionally serves the rest via paramiko for scripts that need full KEX.
"""
import argparse
import os
import socket
import struct
import threading

def ssh_packet(payload):
    """Build an SSH binary packet (no MAC, cipher=none, zlib@none)."""
    # packet = length(4) + padding_len(1) + payload + padding
    block = 8
    min_pad = 4
    padlen = block - ((5 + len(payload)) % block)
    if padlen < min_pad:
        padlen += block
    padding = b"\x00" * padlen
    ln = 1 + len(payload) + padlen
    return struct.pack(">I", ln) + bytes([padlen]) + payload + padding

def name_list(names):
    b = b",".join(names)
    return struct.pack(">I", len(b)) + b

MSG_KEXINIT = 20
MSG_KEXDH_INIT = 30
MSG_KEXDH_REPLY = 31
MSG_NEWKEYS = 21

def hostile_kexinit(variant):
    if variant == "long":
        # algorithm names up to ~900 bytes each
        algos = lambda base: [base + b"A" * 200]
        cookie = b"C" * 16
        payload = bytes([MSG_KEXINIT]) + cookie
        lists = [
            algos(b"kex-"), algos(b"host-"), algos(b"cipher-"),
            algos(b"cipher-"), algos(b"mac-"), algos(b"mac-"),
            algos(b"comp-"), algos(b"comp-"), algos(b"lang-"), algos(b"lang-"),
        ]
        for l in lists:
            payload += name_list(l)
        payload += b"\x00"  # first_kex_packet_follows
        payload += struct.pack(">I", 0)  # reserved
    elif variant == "many":
        cookie = b"D" * 16
        payload = bytes([MSG_KEXINIT]) + cookie
        lists = [
            [b"algo%d" % i for i in range(90)] for _ in range(10)
        ]
        for l in lists:
            payload += name_list(l)
        payload += b"\x00" + struct.pack(">I", 0)
    elif variant == "junk":
        cookie = bytes(range(16))
        payload = bytes([MSG_KEXINIT]) + cookie
        names = [bytes([0x80, 0xff, 0x00, 0x41]), b"\xc3\xa9\xe2\x82\xac", b"x" * 8]
        lists = [names] * 10
        for l in lists:
            payload += name_list(l)
        payload += b"\x00" + struct.pack(">I", 0)
    else:  # empty
        cookie = b"\x00" * 16
        payload = bytes([MSG_KEXINIT]) + cookie
        for _ in range(10):
            payload += name_list([])
        payload += b"\x00" + struct.pack(">I", 0)
    return payload

def handle(conn, variant, banner, complete_kex):
    try:
        conn.settimeout(15)
        # 1. our hostile banner
        conn.sendall(banner)
        # 2. read client banner
        buf = b""
        while b"\r\n" not in buf and len(buf) < 8192:
            d = conn.recv(256)
            if not d:
                return
            buf += d
        # 3. read client KEXINIT
        hdr = conn.recv(4)
        if len(hdr) < 4:
            return
        ln = struct.unpack(">I", hdr)[0]
        toread = ln
        while toread > 0:
            d = conn.recv(min(toread, 4096))
            if not d:
                return
            toread -= len(d)
        # 4. send hostile KEXINIT
        conn.sendall(ssh_packet(hostile_kexinit(variant)))
        if not complete_kex:
            # keep the connection briefly so libssh2 parses our KEXINIT
            try:
                conn.recv(4096)
            except OSError:
                pass
            return
        # 5. read packets until KEXDH_INIT, reply with hostile KEXDH_REPLY
        while True:
            hdr = conn.recv(4)
            if len(hdr) < 4:
                return
            ln = struct.unpack(">I", hdr)[0]
            body = b""
            while len(body) < ln:
                d = conn.recv(ln - len(body))
                if not d:
                    return
                body += d
            msg_type = body[1] if len(body) > 1 else -1
            if msg_type == MSG_KEXDH_INIT:
                # hostile KEXDH_REPLY: crafted host key blob + f + sig
                hostkey_blob = b"\x00\x00\x00\x07ssh-rsa" + b"\x00\x00\x00\x01\x01" + \
                               b"\x00\x00\x00\x03\x01\x00\x01" + b"\x00\x00\x00\x05\x01\x00\x00\x00\x00"
                f_int = b"\x00\x00\x00\x03\x01\x00\x01"
                sig_blob = b"\x00\x00\x00\x07ssh-rsa" + b"\x00\x00\x00\x05\x01\x00\x00\x00\x00"
                payload = bytes([MSG_KEXDH_REPLY])
                payload += struct.pack(">I", len(hostkey_blob)) + hostkey_blob
                payload += struct.pack(">I", len(f_int)) + f_int
                payload += struct.pack(">I", len(sig_blob)) + sig_blob
                conn.sendall(ssh_packet(payload))
            elif msg_type == MSG_NEWKEYS:
                conn.sendall(ssh_packet(bytes([MSG_NEWKEYS])))
                # after NEWKEYS, subsequent traffic is encrypted; just drain
                try:
                    conn.recv(4096)
                except OSError:
                    pass
                return
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--variant", default="long",
                    choices=["long", "many", "junk", "empty"])
    ap.add_argument("--banner", default=None, help="hex banner")
    ap.add_argument("--complete-kex", action="store_true")
    args = ap.parse_args()

    banner = (bytes.fromhex(args.banner) if args.banner
              else b"SSH-2.0-Hostile_1.0\x01\x02\x03\r\n")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(8)
    print(f"[*] hostile SSH on :{args.port} variant={args.variant} banner={banner[:32]!r}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle,
                        args=(conn, args.variant, banner, args.complete_kex),
                        daemon=True).start()

if __name__ == "__main__":
    main()
