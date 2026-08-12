#!/usr/bin/env bash

set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
artifacts_dir="$root_dir/artifacts"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$artifacts_dir/$timestamp"
target_framework="${DOTNET_TARGET_FRAMEWORK:-net10.0}"
benchmark_repetitions="${BENCHMARK_REPETITIONS:-5}"

if ! [[ "$benchmark_repetitions" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_REPETITIONS must be a positive integer" >&2
  exit 2
fi

mkdir -p "$run_dir"

console_output="$run_dir/console.txt"
tls_output="$run_dir/tls.txt"
summary_markdown="$run_dir/summary.md"
summary_json="$run_dir/summary.json"

echo "Target framework: $target_framework"
echo "Benchmark samples: $benchmark_repetitions"
echo

dotnet restore "$root_dir/raw-kem/postquantumdotnettest.csproj" -p:TargetFramework="$target_framework"
dotnet restore "$root_dir/tls/TlsE2eBenchmark.csproj" -p:TargetFramework="$target_framework"
dotnet build --no-restore -c Release --framework "$target_framework" "$root_dir/raw-kem/postquantumdotnettest.csproj"
dotnet build --no-restore -c Release --framework "$target_framework" "$root_dir/tls/TlsE2eBenchmark.csproj"

: > "$console_output"
: > "$tls_output"

for ((sample_index = 1; sample_index <= benchmark_repetitions; sample_index++)); do
  echo "Running console benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  dotnet run --no-build -c Release --framework "$target_framework" --project "$root_dir/raw-kem/postquantumdotnettest.csproj" | tee -a "$console_output"

  echo
  echo "Running TLS benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  dotnet run --no-build -c Release --framework "$target_framework" --project "$root_dir/tls/TlsE2eBenchmark.csproj" -- --scenario all --iterations 100 | tee -a "$tls_output"
done

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
    --openssl-version "${BENCHMARK_OPENSSL_VERSION:-}"
)

echo
echo "Summary markdown: $summary_markdown"
echo "Summary JSON:      $summary_json"

echo
echo "Done. Reports are in $run_dir"