package main

import (
	"strings"
	"testing"
)

func TestParseTLSScenarioCanonicalizesDotnetLabels(t *testing.T) {
	text := `Running pq scenario...
Average: 1.25 ms/handshake
1 handshakes in 1.25 ms
  Protocol: Tls13
  Cipher suite: TLS_AES_256_GCM_SHA384
  TLS key exchange group: X25519MLKEM768 (restricted via OPENSSL_CONF)
  Server certificate: ECDSA (256-bit)
`

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
