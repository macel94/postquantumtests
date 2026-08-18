#!/usr/bin/env bash

set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
artifacts_dir="${BENCHMARK_ARTIFACTS_DIR:-$root_dir/artifacts}"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$artifacts_dir/$timestamp"
target_framework="${DOTNET_TARGET_FRAMEWORK:-net10.0}"
benchmark_repetitions="${BENCHMARK_REPETITIONS:-5}"
benchmark_iterations="${BENCHMARK_ITERATIONS:-100}"
tls_warmup_iterations="${TLS_WARMUP_ITERATIONS:-1}"
openssl_prefix="${BENCHMARK_OPENSSL_PREFIX:-}"
openssl_version="${BENCHMARK_OPENSSL_VERSION:-}"

if ! [[ "$benchmark_repetitions" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_REPETITIONS must be a positive integer" >&2
  exit 2
fi

if ! [[ "$benchmark_iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_ITERATIONS must be a positive integer" >&2
  exit 2
fi

if ! [[ "$tls_warmup_iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "TLS_WARMUP_ITERATIONS must be a positive integer" >&2
  exit 2
fi

if [[ -n "$openssl_prefix" ]]; then
  if [[ ! -x "$openssl_prefix/bin/openssl" || ! -d "$openssl_prefix/lib" ]]; then
    echo "BENCHMARK_OPENSSL_PREFIX must contain bin/openssl and lib" >&2
    exit 2
  fi

  export LD_LIBRARY_PATH="$openssl_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  selected_openssl_version=$("$openssl_prefix/bin/openssl" version | awk '{ print $2 }')
  if [[ -n "$openssl_version" && "$selected_openssl_version" != "$openssl_version" ]]; then
    echo "OpenSSL prefix reports $selected_openssl_version, expected $openssl_version" >&2
    exit 2
  fi

  echo "OpenSSL prefix: $openssl_prefix"
  echo "OpenSSL version: $selected_openssl_version"
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

run_raw_benchmark() {
  local scenario="$1"
  local output

  echo "Running $scenario raw benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  output=$(dotnet "$raw_dll" --scenario "$scenario" --iterations "$benchmark_iterations")
  printf '%s\n' "$output" | tee -a "$console_output"

  if [[ "$scenario" == "mlkem" ]] && grep -Fq 'ML-KEM MLKEM-768 support: supported' <<<"$output"; then
    mlkem_supported=true
  fi
}

run_tls_benchmark() {
  local scenario="$1"
  echo "Running $scenario TLS benchmark sample $sample_index/$benchmark_repetitions in Release mode..."
  dotnet "$tls_dll" --scenario "$scenario" --iterations "$benchmark_iterations" --warmup "$tls_warmup_iterations" | tee -a "$tls_output"
}

for ((sample_index = 1; sample_index <= benchmark_repetitions; sample_index++)); do
  mlkem_supported=false
  if (( sample_index % 2 == 1 )); then
    run_raw_benchmark mlkem
    run_raw_benchmark ecdh
    run_tls_benchmark classical
    if [[ "$mlkem_supported" == true ]]; then
      run_tls_benchmark pq
    fi
  else
    run_raw_benchmark ecdh
    run_raw_benchmark mlkem
    if [[ "$mlkem_supported" == true ]]; then
      run_tls_benchmark pq
    fi
    run_tls_benchmark classical
  fi
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