#!/usr/bin/env python3
"""
Banner fuzzer for Nmap version-detection attack surface.

Generates hostile banners, feeds them through the hostile honeypot (cycle
mode), and drives the ASAN-instrumented nmap against it. Records any ASAN
error as a finding with the banner that caused it.
"""
import os
import re
import signal
import subprocess
import sys
import time

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
HP = "/tmp/nmap_research/honeypot.py"
OUTDIR = "/tmp/nmap_research/findings"
PORT = 2121

os.makedirs(OUTDIR, exist_ok=True)

def gen_banners():
    """Yield (name, hex_banner) pairs of hostile banners."""
    B = []
    # 1. Basic FTP/SSH banners to establish baseline matching
    B.append(("ftp_basic", b"220 jungle FTP server (vsftpd 3.0.3)\r\n"))
    B.append(("ssh_long_ver", b"SSH-2.0-OpenSSH_" + b"9." * 40 + b"\r\n"))
    # 2. bindshell match trigger (CMD.EXE backdoor)
    B.append(("bindshell",
              b"Microsoft Windows XP [Version 5.1.2600]\r\n"
              b"(C) Copyright 1985-2600 Microsoft Corp.\r\n\r\n"))
    # 3. hazelcast member lists (SUBST with \n\tMember)
    members = b"\n\tMember 10.0.0.1:5701" * 5
    B.append(("hazelcast",
              b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nCluster [1] {"
              + members + b"}\n\nConnectionCount: 5\nAllConnectionCount: 10\n\r\n"))
    # 4. SonicWall 302 (7-byte findstr SUBST)
    B.append(("sonicwall",
              b"HTTP/1.1 302 Found\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
              b"Server: unknown\r\nLocation: https://x/__extraweb__EPCmicrointerrogatorpage"
              b"?success=%2F__extraweb__EPCmicrointerrogatordata%3Fsuccess%3D%252F"
              b"__extraweb__realmform%253Fresource%253Dres%25252Fmore%2526alias%253Da%2526r0%253D"))
    # 5. Size boundaries around the 4096 exact-allocation branch
    for size in (4095, 4096, 4097, 8192):
        B.append((f"size_{size}", b"A" * size + b"\r\n"))
    # 6. All-bytes banner
    B.append(("all_bytes", bytes(range(256)) * 4))
    # 7. NUL-heavy (tricky for regex/strlen paths)
    B.append(("nul_run", b"SSH-2.0-" + b"\x00" * 64 + b"\r\n"))
    # 8. long digit/dot runs (version captures)
    B.append(("long_dots", b"Version 1" + b".1" * 500 + b"\r\n"))
    # 9. many Set-Cookie headers (aPod match, %20 SUBST)
    cookies = b"".join(
        b"Set-Cookie: C%d=value%%20here; path=/\r\n" % i for i in range(30))
    B.append(("apod_cookies",
              b"HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
              b"Set-Cookie: SiteName64=abc; Expires=Sat, 31 Dec 2050 23:59:59 GMT\r\n"
              + cookies +
              b"CONTENT-LENGTH: 100\r\n\r\n"))
    # 10. HTML title / script-looking banners
    B.append(("html_long_title", b"<html><head><title>" + b"T" * 2000 + b"</title></head></html>"))
    # 11. Long line without EOL
    B.append(("no_eol_16k", b"L" * 16384))
    # 12. Pathological regex input: backtracking bait
    B.append(("regex_bait", (b"aX" * 300) + b"Y" + b"!" * 100))
    return B

def run_nmap(extra_args, logfile):
    """Run ASAN nmap against the honeypot; return (exit, had_asan_error)."""
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:log_path=" + logfile.replace(".log","")
    cmd = [NMAP, "-sV", "--version-intensity", "9", "-p", str(PORT),
           "--host-timeout", "90s", "-Pn"] + extra_args + ["127.0.0.1"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=120, env=env, text=True)
        asan_hit = ("ERROR: AddressSanitizer" in p.stderr or
                    "ERROR: AddressSanitizer" in p.stdout or
                    "SUMMARY: AddressSanitizer" in p.stderr)
        return p.returncode, asan_hit, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

def main():
    banners = gen_banners()
    print(f"[*] {len(banners)} hostile banners ready")
    # Write payloads dir + hexlines for cycle mode
    pdir = "/tmp/nmap_research/payloads"
    os.makedirs(pdir, exist_ok=True)
    hexfile = "/tmp/nmap_research/banners.hex"
    with open(hexfile, "w") as hf:
        for name, b in banners:
            with open(os.path.join(pdir, name + ".bin"), "wb") as f:
                f.write(b)
            hf.write(b.hex() + "\n")
    print(f"[*] payloads written to {pdir}")

    # Start honeypot in cycle mode over all payloads
    hp = subprocess.Popen(
        [sys.executable, HP, "--ports", str(PORT), "--hexlines", hexfile, "--cycle"],
        stdout=open("/tmp/nmap_research/hp_fuzz.log", "w"),
        stderr=subprocess.STDOUT)
    time.sleep(1)
    print(f"[*] honeypot cycling {len(banners)} payloads, pid={hp.pid}")

    findings = 0
    for i, (name, b) in enumerate(banners):
        # restart honeypot to force THIS banner as the connect-banner
        hp.terminate(); hp.wait()
        hp = subprocess.Popen(
            [sys.executable, HP, "--ports", str(PORT), "--banner", b.hex()],
            stdout=open("/tmp/nmap_research/hp_fuzz.log", "w"),
            stderr=subprocess.STDOUT)
        time.sleep(0.4)
        logf = f"/tmp/nmap_research/findings/{name}.log"
        rc, asan_hit, out = run_nmap([], logf)
        status = "ASAN HIT!" if asan_hit else ("timeout" if rc == -1 else f"rc={rc}")
        print(f"[{i+1}/{len(banners)}] {name:18s} len={len(b):6d} -> {status}")
        with open(logf, "w") as f:
            f.write(out)
        if asan_hit:
            findings += 1
            with open(f"{OUTDIR}/{name}.banner", "wb") as f:
                f.write(b)
    hp.terminate(); hp.wait()
    print(f"[*] done: {findings} ASAN findings out of {len(banners)} banners")

if __name__ == "__main__":
    main()
