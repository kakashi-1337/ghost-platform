#!/usr/bin/env python3
"""
Hostile honeypot responder for Nmap attack-surface research.

When nmap scans us, we control every byte we send back. This responder:
  1. Listens on configurable TCP ports.
  2. Immediately sends an attacker-crafted banner (the data nmap's version
     detection parses) on connect -- mimicking servers that greet first
     (FTP, SMTP, SSH, POP3, IMAP, etc.).
  3. Echoes attacker-crafted responses to NULL-probe / known probe bytes.
  4. Supports cycling banners from a directory so we can drive thousands of
     crafted variants per run.
"""
import argparse
import os
import socket
import ssl
import sys
import threading
import time

def load_payloads(dirpath):
    """Load all payload files from a directory, sorted by name."""
    payloads = []
    if not dirpath:
        return payloads
    for name in sorted(os.listdir(dirpath)):
        p = os.path.join(dirpath, name)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                payloads.append(f.read())
    return payloads

def load_hexlines(path):
    """Load hex-encoded lines from a file (one payload per line)."""
    out = []
    if not path or not os.path.isfile(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                out.append(bytes.fromhex(line))
            except ValueError:
                pass
    return out

class Honeypot:
    def __init__(self, banner, payloads, ports, tls=False, cycle=False, delay=0.0):
        self.banner = banner          # bytes sent immediately on connect (NULL probe reply)
        self.payloads = payloads     # list of alternate banners to cycle
        self.ports = ports
        self.tls = tls
        self.cycle = cycle           # cycle through payloads per connection
        self.delay = delay
        self.counter = 0
        self.lock = threading.Lock()

    def current_banner(self):
        if not self.payloads:
            return self.banner
        with self.lock:
            idx = self.counter if not self.cycle else self.counter % len(self.payloads)
            b = self.payloads[idx]
            self.counter += 1
            return b

    def serve_port(self, port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)
        print(f"[*] listening on 127.0.0.1:{port} tls={self.tls}", flush=True)
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                return
            t = threading.Thread(target=self.handle, args=(conn, addr), daemon=True)
            t.start()

    def handle(self, conn, addr):
        try:
            conn.settimeout(10)
            if self.tls:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain("/tmp/nmap_research/hp_cert.pem", "/tmp/nmap_research/hp_key.pem")
                    conn = ctx.wrap_socket(conn, server_side=True)
                except Exception:
                    pass
            if self.delay:
                time.sleep(self.delay)
            b = self.current_banner()
            if b:
                conn.sendall(b)
            # Read probe bytes nmap sends, then optionally send a second crafted chunk
            try:
                data = conn.recv(4096)
                if data and self.payloads:
                    # respond to any probe with the next crafted payload
                    b2 = self.current_banner()
                    if b2:
                        conn.sendall(b2)
            except OSError:
                pass
        except Exception as e:
            print(f"[!] conn error: {e}", file=sys.stderr, flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def run(self):
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.serve_port, args=(port,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

def main():
    ap = argparse.ArgumentParser(description="Hostile honeypot responder for nmap attack research")
    ap.add_argument("--ports", default="21,22,25,80,110,143,443,993,3306,8080",
                    help="comma-separated TCP ports to listen on")
    ap.add_argument("--banner", default=None, help="hex banner to send on connect")
    ap.add_argument("--banner-file", default=None, help="binary file with banner")
    ap.add_argument("--payloads-dir", default=None, help="directory of payload files to cycle")
    ap.add_argument("--hexlines", default=None, help="file with hex payloads one per line")
    ap.add_argument("--tls", action="store_true", help="wrap in TLS")
    ap.add_argument("--cycle", action="store_true", help="cycle payloads per connection")
    ap.add_argument("--delay", type=float, default=0.0, help="delay before banner (s)")
    args = ap.parse_args()

    banner = b""
    if args.banner:
        banner = bytes.fromhex(args.banner)
    elif args.banner_file:
        banner = open(args.banner_file, "rb").read()
    payloads = load_payloads(args.payloads_dir) + load_hexlines(args.hexlines)
    if not banner and payloads:
        banner = payloads[0]

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    hp = Honeypot(banner, payloads, ports, tls=args.tls, cycle=args.cycle, delay=args.delay)
    print(f"[*] honeypot up: banner={len(banner)}B payloads={len(payloads)} ports={ports}", flush=True)
    hp.run()

if __name__ == "__main__":
    main()
