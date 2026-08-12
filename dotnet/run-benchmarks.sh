#!/usr/bin/env bash

set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
artifacts_dir="$root_dir/artifacts"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$artifacts_dir/$timestamp"
target_framework="${DOTNET_TARGET_FRAMEWORK:-net10.0}"
benchmark_started_ns=$(date +%s%N)

mkdir -p "$run_dir"

console_output="$run_dir/console.txt"
tls_output="$run_dir/tls.txt"
summary_markdown="$run_dir/summary.md"
summary_json="$run_dir/summary.json"

echo "Target framework: $target_framework"
echo

dotnet restore "$root_dir/raw-kem/postquantumdotnettest.csproj" -p:TargetFramework="$target_framework"
dotnet restore "$root_dir/tls/TlsE2eBenchmark.csproj" -p:TargetFramework="$target_framework"

echo "Running console benchmark in Release mode..."
dotnet run --no-restore -c Release --framework "$target_framework" --project "$root_dir/raw-kem/postquantumdotnettest.csproj" | tee "$console_output"

echo
echo "Running TLS benchmark in Release mode..."
dotnet run --no-restore -c Release --framework "$target_framework" --project "$root_dir/tls/TlsE2eBenchmark.csproj" -- --scenario all --iterations 100 | tee "$tls_output"

go_tool_dir="$root_dir/../go"
(
  cd "$go_tool_dir"
  go run ./cmd/benchmarkcompare dotnet \
    --console "$console_output" \
    --tls "$tls_output" \
    --markdown "$summary_markdown" \
    --json "$summary_json" \
    --runtime "$target_framework" \
    --runtime-channel "${BENCHMARK_RUNTIME_CHANNEL:-unknown}" \
    --openssl-version "${BENCHMARK_OPENSSL_VERSION:-}" \
    --started-ns "$benchmark_started_ns" \
    --finished-ns "$(date +%s%N)"
)

echo
echo "Summary markdown: $summary_markdown"
echo "Summary JSON:      $summary_json"

echo
echo "Done. Reports are in $run_dir"