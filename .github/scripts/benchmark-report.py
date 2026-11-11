#!/usr/bin/env python3
"""Converts benchmark CSV results to a Markdown PR comment.

Usage: benchmark-report.py results.csv exit_status

The CSV is written by SecureArithmeticBenchmarks.jl's `write_csv`.
Columns are read by *name*, not by position, so inserting or reordering columns upstream
cannot silently break the report. 
The `error` column is CSV-escaped upstream (quoted when it contains a comma or a quote),
thus we parse it using the `csv` module rather than by splitting on commas.

Errored runs have `status = error` with zeros in every metric and `result_level = -1`.
Such rows are listed separately instead of being reported as a run that took no time.
Configurations killed by the memory limit contribute no rows at all
and are therefore visible only in the workflow's step log.
"""

import csv
import io
import os
import re
import sys

MARKER = "<!-- benchmark-results -->"
TITLE = "# Benchmark Results: SecureArithmetic Matrix Multiplication"
FOOTER = "_Benchmarks run with `OMP_NUM_THREADS=1` on `ubuntu-latest`._"

# Em dash stands in for a value the CSV did not provide.
DASH = "—"

SUMMARY_COLUMNS = ("fhe_params", "matrix_size", "mode", "wall_time_s", "alloc_bytes",
                   "eval_mult_count", "eval_rotate_count", "result_level")
ERROR_COLUMNS = ("status", "error")


def format_alloc(value):
    """Byte count as B/KiB/MiB/GiB, mirroring `format_alloc` in SecureArithmeticBenchmarks.jl."""
    try:
        num = int(float(value))
    except (TypeError, ValueError):
        return DASH
    for limit, unit in ((1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")):
        if num >= limit:
            return "%.1f %s" % (num / limit, unit)
    return "%d B" % num


def format_ms(value):
    """Seconds as milliseconds with one decimal; sub-millisecond runs stay distinguishable."""
    try:
        return "%.1f" % (float(value) * 1000.0)
    except (TypeError, ValueError):
        return DASH


def format_int(value):
    try:
        return str(int(float(value)))
    except (TypeError, ValueError):
        return DASH


def inline_code(text):
    """`text` as a Markdown code span that is safe inside a table cell.

    Pipes must be backslash-escaped even within a code span, because GFM splits table cells
    before it looks for spans. The fence is grown past the longest backtick run in `text` so
    that a message containing backticks cannot end the span early.
    """
    text = " ".join(str(text).split())
    if not text:
        return ""
    cell = text.replace("|", "\\|")
    runs = re.findall(r"`+", cell)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    pad = " " if cell.startswith("`") or cell.endswith("`") else ""
    return fence + pad + cell + pad + fence


def table(header, alignments, rows):
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join(alignments) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def summary_table(rows):
    body = [[row.get("fhe_params", DASH) or DASH,
             row.get("matrix_size", DASH) or DASH,
             row.get("mode", DASH) or DASH,
             format_ms(row.get("wall_time_s")),
             format_alloc(row.get("alloc_bytes")),
             format_int(row.get("eval_mult_count")),
             format_int(row.get("eval_rotate_count")),
             format_int(row.get("result_level"))] for row in rows]
    return table(["FHE Params", "Matrix Size", "Mode", "Wall Time (ms)", "Alloc",
                  "#Mult", "#Rotate", "Result Level"],
                 [":-----------", ":------------", ":-----", "---------------:",
                  "------:", "------:", "--------:", "-------------:"],
                 body)


def error_table(rows):
    body = []
    for row in rows:
        # An unexpected status with no message of its own still has something to report.
        message = (row.get("error") or "").strip() or \
            "status: %s" % (row.get("status") or DASH)
        body.append([row.get("fhe_params", DASH) or DASH,
                     row.get("matrix_size", DASH) or DASH,
                     row.get("mode", DASH) or DASH,
                     inline_code(message)])
    return table(["FHE Params", "Matrix Size", "Mode", "Error"],
                 [":-----------", ":------------", ":-----", ":------"],
                 body)


def main(argv):
    csv_path = argv[1] if len(argv) > 1 else "results.csv"
    status = argv[2] if len(argv) > 2 else "0"

    out = [MARKER, TITLE, ""]
    if status != "0":
        out += ["> **Warning**: Benchmark run exited with status %s." % status, ""]

    if not os.path.isfile(csv_path):
        out += ["No results file found. The benchmark may have failed before producing "
                "output.", ""]
        return out

    with open(csv_path, newline="", encoding="utf-8") as handle:
        raw = handle.read()
    reader = csv.DictReader(io.StringIO(raw))
    fieldnames = reader.fieldnames or []
    rows = list(reader)

    if not rows:
        out += ["No benchmark runs were recorded.", ""]
        return out

    # A column that vanished upstream is reported once, here, rather than as a column of
    # em dashes whose cause has to be guessed.
    missing = [name for name in SUMMARY_COLUMNS + ERROR_COLUMNS if name not in fieldnames]
    if missing:
        out += ["> **Warning**: the results file is missing expected column(s): %s. The "
                "report may be incomplete." % ", ".join("`%s`" % name for name in missing),
                ""]

    # Anything that is not an `ok` run is listed as a run without a result, so an unknown
    # status cannot pass for a successful run.
    completed = [row for row in rows if (row.get("status") or "ok") == "ok"]
    incomplete = [row for row in rows if (row.get("status") or "ok") != "ok"]

    out += ["## Summary", ""]
    if completed:
        out += summary_table(completed)
    else:
        out += ["No run produced a result."]
    out += [""]

    if incomplete:
        out += ["## Runs Without a Result", "",
                "%d of %d runs did not produce a result." % (len(incomplete), len(rows)),
                ""]
        out += error_table(incomplete)
        out += [""]

    out += ["<details>", "<summary>Full results (all columns)</summary>", "",
            "```csv", raw.strip("\n"), "```", "", "</details>", ""]
    return out


if __name__ == "__main__":
    report = main(sys.argv)
    print("\n".join(report + [FOOTER]))
