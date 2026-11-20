#!/bin/bash
# GHOST SOAK — permanent fuzzing campaign across all harnesses.
# Runs every harness indefinitely with rotating corpora, monitoring for
# crashes. Any crash artifact (crash-*) is preserved per harness dir.

BASE=/tmp/nmap_research
cd "$BASE" || exit 1

declare -A HARNESSES=(
    [fuzz_shippedprobes]=corpus_sp     # REAL victim config: shipped 11,969 probes vs hostile banners
    [fuzz_matchpipeline]=corpus_mp     # template machinery ($1/$P/$SUBST/$I/CPE)
    [fuzz_netutil]=corpus              # packet parsers
    [fuzz_dns]=corpus_dns              # DNS response parser
    [fuzz_servicescan2]=corpus_ss     # banner accumulation pipeline
)

for h in "${!HARNESSES[@]}"; do
    dir="${BASE}/soak_$h"
    mkdir -p "$dir"
    corpus="${BASE}/${HARNESSES[$h]}"
    if [[ -x "$BASE/$h" && -d "$corpus" ]]; then
        echo "[$(date +%H:%M:%S)] soaking $h (corpus: ${HARNESSES[$h]})" >> "$BASE/soak.log"
        (
            cd "$dir" && exec "$BASE/$h" "$corpus" \
                -max_len=16384 -rss_limit_mb=4096 -detect_leaks=0 \
                -artifact_prefix="$dir/" -print_final_stats=1 \
                >> "$BASE/soak_$h.log" 2>&1
        ) &
        echo $! >> "$BASE/soak.pids"
    fi
done

echo "[$(date +%H:%M:%S)] all soaks launched" >> "$BASE/soak.log"
wait
