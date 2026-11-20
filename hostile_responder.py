#!/usr/bin/env python3
"""
Hostile Responder — payload-file driven, per the user's design.

Serves whatever bytes the LLM crafts into current_fuzz_payload.bin to every
nmap connection. Improved over the sample: no break after one connection
(nmap sends many probes per scan; each must see the hostile payload), and
an optional probe-echo mode for Vector A/C shaping.
"""
import socket
import sys
import time
import threading
import os

HOST = '127.0.0.1'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
PAYLOAD_FILE = '/tmp/nmap_research/current_fuzz_payload.bin'

def load_payload():
    try:
        with open(PAYLOAD_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return b"SSH-2.0-OpenSSH_8.4p1 Ubuntu-3ubuntu1\r\n"

def handle(client_sock):
    try:
        client_sock.settimeout(4.0)
        # read the probe nmap sends (may or may not arrive)
        try:
            incoming = client_sock.recv(2048)
        except socket.timeout:
            incoming = b""
        payload = load_payload()
        client_sock.sendall(payload)
        time.sleep(0.3)
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
        server.listen(16)
        print(f"[*] Hostile Responder active on {HOST}:{PORT} (payload: {PAYLOAD_FILE})", flush=True)
    except Exception as e:
        print(f"[-] Bind failed: {e}")
        sys.exit(1)
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    start_honeypot()
