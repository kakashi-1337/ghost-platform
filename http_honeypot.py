#!/usr/bin/env python3
"""
Hostile HTTP/TLS responder for NSE script attack research.

Serves attacker-crafted HTTP responses (hostile headers, oversized values,
header count abuse, chunked encoding tricks) and optional TLS with a
crafted certificate chain, to drive nmap NSE scripts (http-*, ssl-cert).
"""
import argparse
import http.server
import os
import ssl
import threading

def make_handler(body, extra_headers, status=200):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra_headers:
                try:
                    self.send_header(k, v)
                except Exception:
                    pass
            self.end_headers()
            self.wfile.write(body)
        do_POST = do_GET
        do_HEAD = do_GET
        do_OPTIONS = do_GET
        def log_message(self, *a):
            pass
    return H

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--body", default="<html><head><title>Hostile</title></head><body>OK</body></html>")
    ap.add_argument("--body-hex", default=None)
    ap.add_argument("--header", action="append", default=[],
                    help="extra header as 'Name:Value' (repeatable)")
    ap.add_argument("--status", type=int, default=200)
    ap.add_argument("--tls", action="store_true")
    args = ap.parse_args()

    body = bytes.fromhex(args.body_hex) if args.body_hex else args.body.encode()
    headers = []
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers.append((k, v))

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port),
                                            make_handler(body, headers, args.status))
    print(f"[*] hostile HTTP on 127.0.0.1:{args.port} tls={args.tls} body={len(body)}B hdrs={len(headers)}", flush=True)
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("/tmp/nmap_research/hp_cert2.pem", "/tmp/nmap_research/hp_key2.pem")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
