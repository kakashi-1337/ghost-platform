#!/usr/bin/env python3
"""
NSE mega-sweep fuzzer: drives ALL nmap scripts against a hostile HTTP server
that returns mutation-rich responses (oversized headers, huge bodies, hostile
content types, chunked abuse), under ASAN. Records ASAN findings.
"""
import os
import random
import string
import subprocess
import sys
import time
import http.server

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
OUT = "/tmp/nmap_research/nse_findings"
os.makedirs(OUT, exist_ok=True)

class HostileHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    fuzz_state = {"n": 0}

    def _body(self):
        n = self.fuzz_state["n"]
        self.fuzz_state["n"] += 1
        # rotate hostile bodies
        if n % 5 == 0:
            return b"<html><head><title>" + b"X" * 5000 + b"</title></head></html>"
        if n % 5 == 1:
            return b"A" * 30000  # big body
        if n % 5 == 2:
            return bytes(random.randbytes(4096))  # binary junk
        if n % 5 == 3:
            return b"<xml>" + b"Z" * 8000 + b"</xml>"
        return b"OK"

    def _respond(self):
        body = self._body()
        n = self.fuzz_state["n"]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if n % 4 == 0:
            self.send_header("X-Hostile", "V" * 8000)
        if n % 4 == 1:
            for i in range(60):
                self.send_header(f"X-Multi-{i}", "M" * 200)
        if n % 4 == 2:
            self.send_header("Set-Cookie", "a=" + "c" * 3000 + "; path=/")
        if n % 4 == 3:
            self.send_header("Location", "http://h/" + "l" * 1000)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_OPTIONS = _respond
    do_PUT = do_DELETE = do_TRACE = _respond
    def log_message(self, *a):
        pass

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), HostileHandler)
    print(f"[*] hostile mutating HTTP on :{port}", flush=True)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
