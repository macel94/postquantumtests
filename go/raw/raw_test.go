package raw

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

const rawIterations = 100

func TestMLKEM768RoundTrip(t *testing.T) {
	serverKey, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM-768 key: %v", err)
	}

	publicKeyBytes := append([]byte(nil), serverKey.EncapsulationKey().Bytes()...)
	for iteration := 0; iteration < rawIterations; iteration++ {
		publicKey, err := mlkem.NewEncapsulationKey768(publicKeyBytes)
		if err != nil {
			t.Fatalf("parse ML-KEM-768 encapsulation key on iteration %d: %v", iteration, err)
		}

		clientSecret, ciphertext := publicKey.Encapsulate()
		serverSecret, err := serverKey.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("decapsulate ML-KEM-768 ciphertext on iteration %d: %v", iteration, err)
		}

		if !bytes.Equal(clientSecret, serverSecret) {
			t.Fatalf("ML-KEM-768 shared secrets differ on iteration %d", iteration)
		}
	}
}

func BenchmarkMLKEM768RoundTrip(b *testing.B) {
	serverKey, err := mlkem.GenerateKey768()
	if err != nil {
		b.Fatalf("generate ML-KEM-768 key: %v", err)
	}
	publicKeyBytes := append([]byte(nil), serverKey.EncapsulationKey().Bytes()...)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		publicKey, err := mlkem.NewEncapsulationKey768(publicKeyBytes)
		if err != nil {
			b.Fatalf("parse ML-KEM-768 encapsulation key: %v", err)
		}

		clientSecret, ciphertext := publicKey.Encapsulate()
		serverSecret, err := serverKey.Decapsulate(ciphertext)
		if err != nil {
			b.Fatalf("decapsulate ML-KEM-768 ciphertext: %v", err)
		}

		if !bytes.Equal(clientSecret, serverSecret) {
			b.Fatal("ML-KEM-768 shared secrets differ")
		}
	}
}

func TestECDHP256RoundTrip(t *testing.T) {
	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDH P-256 key: %v", err)
	}

	for iteration := 0; iteration < rawIterations; iteration++ {
		clientKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate client ECDH P-256 key on iteration %d: %v", iteration, err)
		}

		clientSecret, err := clientKey.ECDH(serverKey.PublicKey())
		if err != nil {
			t.Fatalf("derive client ECDH P-256 secret on iteration %d: %v", iteration, err)
		}
		serverSecret, err := serverKey.ECDH(clientKey.PublicKey())
		if err != nil {
			t.Fatalf("derive server ECDH P-256 secret on iteration %d: %v", iteration, err)
		}

		if !bytes.Equal(clientSecret, serverSecret) {
			t.Fatalf("ECDH P-256 shared secrets differ on iteration %d", iteration)
		}
	}
}

func BenchmarkECDHP256RoundTrip(b *testing.B) {
	serverKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate ECDH P-256 key: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		clientKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("generate client ECDH P-256 key: %v", err)
		}

		clientSecret, err := clientKey.ECDH(serverKey.PublicKey())
		if err != nil {
			b.Fatalf("derive client ECDH P-256 secret: %v", err)
		}
		serverSecret, err := serverKey.ECDH(clientKey.PublicKey())
		if err != nil {
			b.Fatalf("derive server ECDH P-256 secret: %v", err)
		}

		if !bytes.Equal(clientSecret, serverSecret) {
			b.Fatal("ECDH P-256 shared secrets differ")
		}
	}
}
