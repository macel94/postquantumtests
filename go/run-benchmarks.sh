#!/usr/bin/env bash

set -euo pipefail

benchmark_repetitions="${BENCHMARK_REPETITIONS:-5}"
benchmark_iterations="${BENCHMARK_ITERATIONS:-100}"
build_dir=$(mktemp -d)
results_path="${BENCHMARK_RESULTS_PATH:-benchmark-results.txt}"
record_path="${BENCHMARK_RECORD_PATH:-benchmark-record.json}"

trap 'rm -rf "$build_dir"' EXIT

if ! [[ "$benchmark_repetitions" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_REPETITIONS must be a positive integer" >&2
  exit 2
fi

if ! [[ "$benchmark_iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_ITERATIONS must be a positive integer" >&2
  exit 2
fi

go mod download

go clean -cache -testcache
clean_build_started_ns=$(date +%s%N)
go test -c -o "$build_dir/raw.test" ./raw
go test -c -o "$build_dir/tls.test" ./tls
clean_build_finished_ns=$(date +%s%N)
clean_build_ms=$(awk "BEGIN { printf \"%.3f\", ($clean_build_finished_ns - $clean_build_started_ns) / 1000000 }")

cached_build_started_ns=$(date +%s%N)
go test -c -o "$build_dir/raw.test" ./raw
go test -c -o "$build_dir/tls.test" ./tls
cached_build_finished_ns=$(date +%s%N)
cached_build_ms=$(awk "BEGIN { printf \"%.3f\", ($cached_build_finished_ns - $cached_build_started_ns) / 1000000 }")

: > "$results_path"
benchmark_started_ns=$(date +%s%N)
for ((sample_index = 1; sample_index <= benchmark_repetitions; sample_index++)); do
  echo "Running Go raw benchmark sample $sample_index/$benchmark_repetitions..."
  "$build_dir/raw.test" \
    -test.run '^$' \
    -test.bench '^Benchmark(MLKEM768RoundTrip|ECDHP256RoundTrip)$' \
    -test.benchmem \
    -test.benchtime="${benchmark_iterations}x" \
    -test.count=1 | tee -a "$results_path"

  echo "Running Go TLS benchmark sample $sample_index/$benchmark_repetitions..."
  "$build_dir/tls.test" \
    -test.run '^$' \
    -test.bench '^BenchmarkTLS13(ClassicalEcho|HybridMLKEM768Echo)$' \
    -test.benchmem \
    -test.benchtime="${benchmark_iterations}x" \
    -test.count=1 | tee -a "$results_path"
done
benchmark_finished_ns=$(date +%s%N)
benchmark_elapsed_ms=$(awk "BEGIN { printf \"%.3f\", ($benchmark_finished_ns - $benchmark_started_ns) / 1000000 }")

go run ./cmd/benchmarkcompare go \
  --input "$results_path" \
  --output "$record_path" \
  --runtime "$(go version | awk '{ print $3 }')" \
  --benchmark-elapsed-ms "$benchmark_elapsed_ms" \
  --clean-build-ms "$clean_build_ms" \
  --cached-build-ms "$cached_build_ms"

echo "Benchmark ms:     $benchmark_elapsed_ms"
echo "Clean build ms:   $clean_build_ms"
echo "Cached build ms:  $cached_build_ms"