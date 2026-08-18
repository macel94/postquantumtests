#!/usr/bin/env bash

set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
artifacts_dir="$root_dir/artifacts"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$artifacts_dir/$timestamp"
target_framework="${DOTNET_TARGET_FRAMEWORK:-net10.0}"
benchmark_repetitions="${BENCHMARK_REPETITIONS:-5}"
benchmark_iterations="${BENCHMARK_ITERATIONS:-100}"

if ! [[ "$benchmark_repetitions" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_REPETITIONS must be a positive integer" >&2
  exit 2
fi

if ! [[ "$benchmark_iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_ITERATIONS must be a positive integer" >&2
  exit 2
fi

mkdir -p "$run_dir"

console_output="$run_dir/console.txt"
tls_output="$run_dir/tls.txt"
summary_markdown="$run_dir/summary.md"
summary_json="$run_dir/summary.json"

echo "Target framework: $target_framework"
echo "Benchmark samples: $benchmark_repetitions"
echo "Benchmark iterations: $benchmark_iterations"
echo

dotnet restore "$root_dir/raw-kem/postquantumdotnettest.csproj" -p:TargetFramework="$target_framework"
dotnet restore "$root_dir/tls/TlsE2eBenchmark.csproj" -p:TargetFramework="$target_framework"

rm -rf "$root_dir/raw-kem/bin" "$root_dir/raw-kem/obj/Release"
rm -rf "$root_dir/tls/bin" "$root_dir/tls/obj/Release"

clean_build_started_ns=$(date +%s%N)
dotnet build --no-restore --no-incremental -c Release --framework "$target_framework" "$root_dir/raw-kem/postquantumdotnettest.csproj"
dotnet build --no-restore --no-incremental -c Release --framework "$target_framework" "$root_dir/tls/TlsE2eBenchmark.csproj"
clean_build_finished_ns=$(date +%s%N)
clean_build_ms=$(awk "BEGIN { printf \"%.3f\", ($clean_build_finished_ns - $clean_build_started_ns) / 1000000 }")

cached_build_started_ns=$(date +%s%N)
dotnet build --no-restore -c Release --framework "$target_framework" "$root_dir/raw-kem/postquantumdotnettest.csproj"
dotnet build --no-restore -c Release --framework "$target_framework" "$root_dir/tls/TlsE2eBenchmark.csproj"
cached_build_finished_ns=$(date +%s%N)
cached_build_ms=$(awk "BEGIN { printf \"%.3f\", ($cached_build_finished_ns - $cached_build_started_ns) / 1000000 }")

: > "$console_output"
: > "$tls_output"

raw_dll="$root_dir/raw-kem/bin/Release/$target_framework/postquantumdotnettest.dll"
tls_dll="$root_dir/tls/bin/Release/$target_framework/TlsE2eBenchmark.dll"
benchmark_started_ns=$(date +%s%N)
for ((sample_index = 1; sample_index <= benchmark_repetitions; sample_index++)); do
  echo "Running console benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  dotnet "$raw_dll" --iterations "$benchmark_iterations" | tee -a "$console_output"

  echo
  echo "Running TLS benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  dotnet "$tls_dll" --scenario all --iterations "$benchmark_iterations" --warmup 0 | tee -a "$tls_output"
done
benchmark_finished_ns=$(date +%s%N)
benchmark_elapsed_ms=$(awk "BEGIN { printf \"%.3f\", ($benchmark_finished_ns - $benchmark_started_ns) / 1000000 }")

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
    --benchmark-elapsed-ms "$benchmark_elapsed_ms" \
    --clean-build-ms "$clean_build_ms" \
    --cached-build-ms "$cached_build_ms"
)

echo
echo "Summary markdown: $summary_markdown"
echo "Summary JSON:      $summary_json"
echo "Benchmark ms:      $benchmark_elapsed_ms"
echo "Clean build ms:    $clean_build_ms"
echo "Cached build ms:   $cached_build_ms"

echo
echo "Done. Reports are in $run_dir"