# GHOST — Hostile Scan-Response Attack Platform

*"Hindi tayo auditor. HACKER/RESEARCHER tayo."*

Isang automated attack platform para sa **hostile scan-response research** laban sa Nmap (o kahit anong scanner). Bawat research idea natin = executable module. Bawat finding = auto-reproducing PoC.

## Quick Start

```bash
# Full battery (unprivileged) laban sa ASAN-instrumented nmap:
python3 attack_platform.py --nmap /path/to/nmap

# Isang module lang:
python3 attack_platform.py --only subst_oob

# Kasama ang docker privileged surfaces (raw OS detection, DNS:53, SMB:445):
python3 attack_platform.py

# Listahan ng modules:
python3 attack_platform.py --list
```

## Modules

| Module | Tags | Describes |
|---|---|---|
| `banner_battery` | vector_a | 10 hostile banners (60KB captures, control chars, boundaries) through `-sV` under ASAN |
| `subst_oob` | poc, regression | **ANG NATAGPUANG BUG**: heap-buffer-overflow READ sa `service_scan.cc:813` (substvar SUBST memcmp). Custom probe file na ang capture group ay nagtatapos sa last byte ng banner + multi-char findstr + ≥4096 exact allocation. Deterministic. |
| `nse_http_battery` | vector_b | Lahat ng http-* NSE scripts laban sa mutating hostile HTTP |
| `ssh_kex_battery` | vector_c | Hostile SSH KEXINIT variants (long/junk/empty) laban sa libssh2 |
| `escape_injection` | terminal | Terminal escape injection detector — banner na may ESC/OSC/DSR, sinusuri ang stdout/-oN/-oG/-oX sa raw ESC bytes |
| `privileged_battery` | docker | Docker privileged: raw-packet OS detection na may hostile TCP options (oversize/weird/extreme), hostile DNS:53, buong SMB sa tunay na port 445 |
| `fuzz_short` | fuzz | 60s coverage-guided fuzz bawat harness (CI-style) |

## Ang Natagpuang Vulnerability

**GHOST-SUBST-001**: heap-buffer-overflow READ — `service_scan.cc:813` (substvar, SUBST handler)

- **Trigger**: probe-file match na `$SUBST(n, <multi-char findstr>)` na ang capture group ay makapagtapos sa dulong byte ng response buffer, na ang response accumulation ay tumama sa exact-allocation path (`newlen >= 4096`)
- **Mechanism**: ang SUBST loop ay gumagawa ng `memcmp(subject + i, findstr, findstrlen)` kung saan ang `i` ay umaabot sa `offend - 1`; kung ang group ay nagtatapos sa `subjectlen`, ang huling memcmp ay nagbabasa ng `findstrlen - 1` bytes lampas sa heap buffer
- **Shipped reachability**: HINDI reachable sa kasalukuyang `nmap-service-probes` (lahat ng 209 SUBST groups ay structured na nakalayo sa banner end) — pero **PROVEN reachable** sa custom/bagong probe entry
- **Impact**: OOB read hanggang `findstrlen - 1` bytes (info-leak class)
- **Artifacts**: `subst_oob_asan_report.txt` (ASAN report), `subst_ooc_probe_file.txt` (custom probe), `subst_ooc_banner.bin` (4907-byte banner)

## Mga Artifacts

- `fuzz_netutil`, `fuzz_servicescan2`, `fuzz_dns` — libFuzzer harnesses (packet parsers, banner pipeline, DNS)
- `corpus/`, `corpus_ss/`, `corpus_dns/` — mga fuzzing corpus
- `container_attack.py` — raw-packet hostile responder para sa docker
- `smb_honeypot_container.py` — buong SMB1 state machine para sa real port 445

## Campaign History (nmap 7.993SVN)

- 438,009,742 coverage-guided executions — 0 maliban sa GHOST-SUBST-001
- Lahat ng end-to-end surface: SMB/SSH/TLS/Mongo/redis/VNC/LDAP/UPnP/IPv6/raw-OS-detection/DNS:53/SMB:445
- 6 documented na defense mechanism (cstringSanityCheck, escape_for_screen, atbp.)

*Laban sa bagong nmap release: i-update ang `--nmap`, patakbuhin ang platform, at panoorin ang `subst_oob` — kapag nag-ship sila ng probe entry na may group-end-at-banner-end + multi-char findstr, GHOST-SUBST-001 ay live na info-leak.*
