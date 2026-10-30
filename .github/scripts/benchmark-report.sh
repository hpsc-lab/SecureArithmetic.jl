#!/usr/bin/env bash
# Converts benchmark CSV results to a Markdown PR comment.
# Usage: benchmark-report.sh results.csv exit_status

set -euo pipefail

CSV_FILE="${1:-results.csv}"
STATUS="${2:-0}"

echo "<!-- benchmark-results -->"
echo "# Benchmark Results: SecureArithmetic Matrix Multiplication"
echo ""

if [[ "$STATUS" != "0" ]]; then
    echo "> **Warning**: Benchmark run exited with status $STATUS."
    echo ""
fi

if [[ ! -f "$CSV_FILE" ]]; then
    echo "No results file found. The benchmark may have failed before producing output."
    exit 0
fi

echo "## Summary"
echo ""
echo "| FHE Params | Matrix Size | Mode | Wall Time (ms) | #Mult | #Rotate | Depth |"
echo "|:-----------|:------------|:-----|---------------:|------:|--------:|------:|"

tail -n +2 "$CSV_FILE" | while IFS=, read -r fhe_params matrix_size mode wall_time_s alloc_bytes \
    eval_add_count eval_add_time_s eval_sub_count eval_sub_time_s \
    eval_mult_count eval_mult_time_s eval_rotate_count eval_rotate_time_s \
    eval_negate_count eval_negate_time_s resize_count resize_time_s \
    multiplicative_depth; do
    wall_time_ms=$(awk "BEGIN {printf \"%d\", $wall_time_s * 1000}")
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
        "$fhe_params" "$matrix_size" "$mode" "$wall_time_ms" \
        "$eval_mult_count" "$eval_rotate_count" "$multiplicative_depth"
done

echo ""
echo "<details>"
echo "<summary>Full results (all columns)</summary>"
echo ""
echo '```'
column -t -s, "$CSV_FILE"
echo '```'
echo ""
echo "</details>"
echo ""
echo "_Benchmarks run with \`OMP_NUM_THREADS=1\` on \`ubuntu-latest\`._"
