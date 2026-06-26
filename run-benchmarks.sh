#!/usr/bin/env bash

set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
artifacts_dir="$root_dir/artifacts"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$artifacts_dir/$timestamp"
target_framework="${DOTNET_TARGET_FRAMEWORK:-net10.0}"

mkdir -p "$run_dir"

console_output="$run_dir/console.txt"
tls_output="$run_dir/tls.txt"
summary_markdown="$run_dir/summary.md"
summary_json="$run_dir/summary.json"

echo "Target framework: $target_framework"
echo

echo "Running console benchmark in Release mode..."
dotnet run -c Release --framework "$target_framework" --project "$root_dir/postquantumdotnettest.csproj" | tee "$console_output"

echo
echo "Running TLS benchmark in Release mode..."
dotnet run -c Release --framework "$target_framework" --project "$root_dir/TlsE2eBenchmark/TlsE2eBenchmark.csproj" -- --scenario all --iterations 100 | tee "$tls_output"

python3 - "$console_output" "$tls_output" "$summary_markdown" "$summary_json" <<'PY'
import pathlib
import re
import sys

console_output = pathlib.Path(sys.argv[1]).read_text()
tls_output = pathlib.Path(sys.argv[2]).read_text()
summary_markdown = pathlib.Path(sys.argv[3])
summary_json = pathlib.Path(sys.argv[4])

def extract(pattern: str, text: str, label: str) -> float:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(f"Could not find {label} in benchmark output")
    return float(match.group(1))

def extract_ms_per_round_trip(pattern: str, text: str, label: str) -> float:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(f"Could not find {label} in benchmark output")

    completed = int(match.group(1))
    elapsed_ms = float(match.group(3))
    return elapsed_ms / completed

console_mlkem = extract_ms_per_round_trip(r"ML-KEM ML-KEM-768 benchmark: (\d+)/(\d+) successful round-trips in ([0-9.]+) ms", console_output, "console ML-KEM total time")
console_ecdh = extract_ms_per_round_trip(r"ECDH P-256 benchmark: (\d+)/(\d+) successful round-trips in ([0-9.]+) ms", console_output, "console ECDH total time")
tls_classical = extract(r"Running classical scenario\.[\s\S]*?Average: ([0-9.]+) ms/handshake", tls_output, "TLS classical average")
tls_pq = extract(r"Running pq scenario\.[\s\S]*?Average: ([0-9.]+) ms/handshake", tls_output, "TLS PQ average")

rows = [
    ("Console", "ML-KEM-768", console_mlkem),
    ("Console", "ECDH P-256", console_ecdh),
    ("TLS 1.3", "Classical", tls_classical),
    ("TLS 1.3", "Post-quantum", tls_pq),
]

summary = {
    "console": {
        "mlkem768_ms_per_round_trip": console_mlkem,
        "ecdh_p256_ms_per_round_trip": console_ecdh,
    },
    "tls": {
        "classical_ms_per_handshake": tls_classical,
        "post_quantum_ms_per_handshake": tls_pq,
    },
}

summary_json.write_text(
    "{\n"
    f'  "console": {{\n'
    f'    "mlkem768_ms_per_round_trip": {summary["console"]["mlkem768_ms_per_round_trip"]:.6f},\n'
    f'    "ecdh_p256_ms_per_round_trip": {summary["console"]["ecdh_p256_ms_per_round_trip"]:.6f}\n'
    f'  }},\n'
    f'  "tls": {{\n'
    f'    "classical_ms_per_handshake": {summary["tls"]["classical_ms_per_handshake"]:.6f},\n'
    f'    "post_quantum_ms_per_handshake": {summary["tls"]["post_quantum_ms_per_handshake"]:.6f}\n'
    f'  }}\n'
    "}\n"
)

summary_lines = [
    "# Benchmark Summary",
    "",
    "| Area | Algorithm | Avg ms |",
    "| --- | --- | ---: |",
    f"| Console | ML-KEM-768 | {rows[0][2]:.2f} |",
    f"| Console | ECDH P-256 | {rows[1][2]:.2f} |",
    f"| TLS 1.3 | Classical | {rows[2][2]:.2f} |",
    f"| TLS 1.3 | Post-quantum | {rows[3][2]:.2f} |",
    "",
    "## Relative slowdown",
    "",
    f"- Console PQ vs classical: {rows[0][2] / rows[1][2]:.2f}x",
    f"- TLS PQ vs classical: {rows[3][2] / rows[2][2]:.2f}x",
]
summary_markdown.write_text("\n".join(summary_lines) + "\n")

print()
print("Benchmark summary")
print("-----------------")
for area, label, value in rows:
    print(f"{area:8} {label:15} {value:8.2f} ms")

print()
print("Grouped average-time chart")
print("--------------------------")

max_value = max(value for _, _, value in rows)
scale = 40 / max_value if max_value else 1
for area, label, value in rows:
    bar = "█" * max(1, int(round(value * scale)))
    print(f"{area:8} {label:15} {bar} {value:.2f} ms")

print()
print(f"Summary markdown: {summary_markdown}")
print(f"Summary JSON:      {summary_json}")
PY

echo
echo "Done. Reports are in $run_dir"