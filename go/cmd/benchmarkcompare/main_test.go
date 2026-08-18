package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGoBenchmarksCollectsRepeatedSamples(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "benchmark-results.txt")
	input := strings.Join([]string{
		"BenchmarkMLKEM768RoundTrip-4 100 100 ns/op",
		"BenchmarkMLKEM768RoundTrip-4 100 200 ns/op",
		"BenchmarkECDHP256RoundTrip-4 100 300 ns/op",
		"BenchmarkECDHP256RoundTrip-4 100 400 ns/op",
		"BenchmarkTLS13ClassicalEcho-4 100 500 ns/op",
		"BenchmarkTLS13ClassicalEcho-4 100 600 ns/op",
		"BenchmarkTLS13HybridMLKEM768Echo-4 100 700 ns/op",
		"BenchmarkTLS13HybridMLKEM768Echo-4 100 800 ns/op",
	}, "\n")
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	measurements, err := parseGoBenchmarks(inputPath)
	if err != nil {
		t.Fatalf("parseGoBenchmarks() error = %v", err)
	}
	measurement := measurements["raw_mlkem768"]
	if measurement.Iterations != 100 {
		t.Fatalf("raw_mlkem768 iterations = %v, want 100", measurement.Iterations)
	}
	if len(measurement.SamplesNanoseconds) != 2 || measurement.SamplesNanoseconds[0] != 100 || measurement.SamplesNanoseconds[1] != 200 {
		t.Fatalf("raw_mlkem768 samples = %v, want [100 200]", measurement.SamplesNanoseconds)
	}
}

func TestParseRoundTripCollectsRepeatedSamples(t *testing.T) {
	text := strings.Join([]string{
		"ML-KEM ML-KEM-768 benchmark:",
		"2/2 successful round-trips in 2.00 ms",
		"ML-KEM ML-KEM-768 benchmark:",
		"2/2 successful round-trips in 4.00 ms",
	}, "\n")

	samples, iterations, err := parseRoundTrip(text, `ML-KEM ML-KEM-768 benchmark:`)
	if err != nil {
		t.Fatalf("parseRoundTrip() error = %v", err)
	}
	if iterations != 2 {
		t.Fatalf("iterations = %v, want 2", iterations)
	}
	if len(samples) != 2 || samples[0] != 1 || samples[1] != 2 {
		t.Fatalf("samples = %v, want [1 2]", samples)
	}
}

func TestResultFromSamplesUsesMedian(t *testing.T) {
	measurement, err := resultFromSamples([]float64{1, 4, 2, 3, 5}, 100, "pass")
	if err != nil {
		t.Fatalf("resultFromSamples() error = %v", err)
	}
	if measurement.MedianMS == nil || *measurement.MedianMS != 3 {
		t.Fatalf("median_ms = %v, want 3", measurement.MedianMS)
	}
	if measurement.SampleCount != 5 || len(measurement.SamplesMS) != 5 {
		t.Fatalf("sample metadata = count %d, samples %v; want five samples", measurement.SampleCount, measurement.SamplesMS)
	}
	if measurement.RelativeStdDevPercent == nil || math.Abs(*measurement.RelativeStdDevPercent-52.70462766947299) > 1e-12 {
		t.Fatalf("relative_stddev_percent = %v, want sample RSD", measurement.RelativeStdDevPercent)
	}
}

func TestValidateRecordsRequiresComparableTimingMetrics(t *testing.T) {
	item := record{
		Implementation: "go",
		Runtime:        "go1.26.6",
		RuntimeChannel: "latest-stable",
	}
	if err := validateRecords([]record{item}, false); err == nil {
		t.Fatal("validateRecords() accepted missing comparable timing metrics")
	}

	item.BenchmarkElapsedMS = 10
	item.CleanBuildMS = 20
	item.CachedBuildMS = 5
	if err := validateRecords([]record{item}, false); err != nil {
		t.Fatalf("validateRecords() rejected complete timing metrics: %v", err)
	}
}

func TestParseTLSScenarioCanonicalizesDotnetLabels(t *testing.T) {
	text := strings.Join([]string{
		"Running pq scenario...",
		"Average: 1.25 ms/handshake",
		"1 handshakes in 1.25 ms",
		"  Protocol: Tls13",
		"  Cipher suite: TLS_AES_256_GCM_SHA384",
		"  TLS key exchange group: X25519MLKEM768 (restricted via OPENSSL_CONF)",
		"  Server certificate: ECDSA (256-bit)",
		"",
		"Running pq scenario...",
		"Average: 2.25 ms/handshake",
		"1 handshakes in 2.25 ms",
		"  Protocol: Tls13",
		"  Cipher suite: TLS_AES_256_GCM_SHA384",
		"  TLS key exchange group: X25519MLKEM768 (restricted via OPENSSL_CONF)",
		"  Server certificate: ECDSA (256-bit)",
	}, "\n")

	measurement, err := parseTLSScenario(text, "pq")
	if err != nil {
		t.Fatalf("parseTLSScenario() error = %v", err)
	}
	if measurement.Protocol != "TLS 1.3" {
		t.Fatalf("Protocol = %q, want TLS 1.3", measurement.Protocol)
	}
	if measurement.KeyExchangeGroup != "X25519MLKEM768" {
		t.Fatalf("KeyExchangeGroup = %q, want X25519MLKEM768", measurement.KeyExchangeGroup)
	}
	if measurement.CertificateAlgorithm != "ECDSA P-256" {
		t.Fatalf("CertificateAlgorithm = %q, want ECDSA P-256", measurement.CertificateAlgorithm)
	}
	if measurement.MedianMS != 1.75 {
		t.Fatalf("MedianMS = %v, want 1.75", measurement.MedianMS)
	}
	if len(measurement.SamplesMS) != 2 {
		t.Fatalf("SamplesMS = %v, want two samples", measurement.SamplesMS)
	}
}

func TestValidateTLSPairRequiresComparableScenarios(t *testing.T) {
	classical := tlsMeasurement{
		Protocol:             "TLS 1.3",
		CipherSuite:          "TLS_AES_256_GCM_SHA384",
		KeyExchangeGroup:     "X25519",
		CertificateAlgorithm: "ECDSA P-256",
	}
	tests := []struct {
		name string
		pq   *tlsMeasurement
		want string
	}{
		{
			name: "hybrid group passes",
			pq: &tlsMeasurement{
				Protocol:             "TLS 1.3",
				CipherSuite:          "TLS_AES_256_GCM_SHA384",
				KeyExchangeGroup:     "X25519MLKEM768",
				CertificateAlgorithm: "ECDSA P-256",
			},
		},
		{
			name: "pure KEM is rejected",
			pq: &tlsMeasurement{
				Protocol:             "TLS 1.3",
				CipherSuite:          "TLS_AES_256_GCM_SHA384",
				KeyExchangeGroup:     "MLKEM768",
				CertificateAlgorithm: "ECDSA P-256",
			},
			want: "hybrid X25519MLKEM768",
		},
		{
			name: "different certificate is rejected",
			pq: &tlsMeasurement{
				Protocol:             "TLS 1.3",
				CipherSuite:          "TLS_AES_256_GCM_SHA384",
				KeyExchangeGroup:     "X25519MLKEM768",
				CertificateAlgorithm: "ML-DSA-65",
			},
			want: "unexpected certificate algorithm",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateTLSPair(classical, test.pq)
			if test.want == "" {
				if err != nil {
					t.Fatalf("validateTLSPair() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateTLSPair() error = %v, want substring %q", err, test.want)
			}
		})
	}
}
