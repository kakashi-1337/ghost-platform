#!/usr/bin/env python3
"""
Mutation fuzzer round 2: takes seed banners that match real nmap probe
regexes and mutates around sensitive length boundaries (255/256, 511/512,
1023/1024, 4095/4096/4097), with byte-level mutation. Drives ASAN nmap.
"""
import os
import random
import subprocess
import sys
import time

NMAP = "/home/dave/deepseek-harness/default-workspace/nmap_experiment/nmap/nmap"
HP = "/tmp/nmap_research/honeypot.py"
OUT = "/tmp/nmap_research/mut2"
PORT = 2121
os.makedirs(OUT, exist_ok=True)
random.seed(31337)

def seeds():
    S = []
    S.append(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
    S.append(b"Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001 Microsoft Corp.\r\n\r\n")
    S.append(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    S.append(b"220 jungle FTP server (vsftpd 3.0.3)\r\n")
    S.append(b"\x02\x83\x00vPORT Rev:+D2Tech+ VPORT  VPORT_R_1_2_3 \n")
    S.append(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nCluster [1] {\n\tMember 10.0.0.1:5701}\n\nConnectionCount: 5\nAllConnectionCount: 10\n\r\n")
    return S

def gen_mutations(seed):
    M = []
    base = seed.rstrip(b"\r\n")
    # length boundaries
    for L in (255, 256, 511, 512, 1023, 1024, 4095, 4096, 4097, 8191):
        M.append(("len%d" % L, (base[:64] + b"A" * max(0, L - 64) + b"\r\n")[:L+2]))
    # byte mutations (flip ranges of bytes to hostile values)
    for k in range(12):
        b = bytearray(seed)
        for _ in range(random.randint(1, 8)):
            i = random.randrange(len(b))
            b[i] = random.choice([0x00, 0xFF, 0x80, 0xFE, random.randrange(256)])
        M.append(("flip%d" % k, bytes(b)))
    # NUL injection after prefix
    for k in range(6):
        i = random.randrange(1, max(2, len(seed)))
        M.append(("nul%d" % k, seed[:i] + b"\x00" + b"Z" * 64 + seed[i:]))
    # truncation at boundaries
    for k in range(6):
        i = max(1, random.randrange(len(seed)))
        M.append(("trunc%d" % k, seed[:i]))
    return M

def run_nmap():
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0"
    cmd = [NMAP, "-sV", "--version-intensity", "9", "-p", str(PORT),
           "--host-timeout", "75s", "-Pn", "127.0.0.1"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=100, env=env, text=True)
        asan = "ERROR: AddressSanitizer" in (p.stdout + p.stderr)
        return p.returncode, asan, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, False, "TIMEOUT"

def main():
    total, findings = 0, 0
    for si, seed in enumerate(seeds()):
        muts = gen_mutations(seed)
        for name, banner in muts:
            total += 1
            hp = subprocess.Popen(
                [sys.executable, HP, "--ports", str(PORT), "--banner", banner.hex()],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.35)
            rc, asan, out = run_nmap()
            hp.terminate(); hp.wait()
            tag = "ASAN HIT!" if asan else ("to" if rc == -1 else ".")
            print(f"[{total}] seed{si}/{name:8s} len={len(banner):5d} {tag}", flush=True)
            with open(f"{OUT}/seed{si}_{name}.log", "w") as f:
                f.write(out)
            if asan:
                findings += 1
                with open(f"{OUT}/seed{si}_{name}.banner", "wb") as f:
                    f.write(banner)
    print(f"[*] done: {findings}/{total} findings")

if __name__ == "__main__":
    main()
