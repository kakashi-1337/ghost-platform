#!/bin/bash
# GHOST soak status — ipakita ang progress ng bawat harness at ang mga crash
BASE=/tmp/nmap_research
echo "=== GHOST SOAK STATUS $(date +%H:%M:%S) ==="
for h in fuzz_shippedprobes fuzz_matchpipeline fuzz_netutil fuzz_dns fuzz_servicescan2; do
    log="$BASE/soak_$h.log"
    if [[ -f "$log" ]]; then
        execs=$(grep -oE "#[0-9]+.*" "$log" 2>/dev/null | tail -1 | grep -oE "^#[0-9]+" | tr -d '#')
        cov=$(grep -oE "cov: [0-9]+" "$log" 2>/dev/null | tail -1)
        crashes=$(ls "$BASE/soak_$h/"crash-* 2>/dev/null | wc -l)
        if [[ -z "$execs" ]]; then execs="?"; fi
        printf "%-22s execs=%-12s %-10s crashes=%s\n" "$h" "$execs" "$cov" "$crashes"
    else
        printf "%-22s (not started)\n" "$h"
    fi
done
echo "---"
total_crashes=$(ls "$BASE"/soak_*/crash-* 2>/dev/null | wc -l)
echo "TOTAL CRASHES: $total_crashes"
if [[ "$total_crashes" -gt 0 ]]; then
    echo "*** MAY NATAGPUAN — suriin ang mga ito: ***"
    ls "$BASE"/soak_*/crash-* 2>/dev/null
fi
