package postquantumtests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

const tlsPayloadBytes = 32

type tlsHarness struct {
	listener     net.Listener
	address      string
	serverConfig *tls.Config
	clientConfig *tls.Config
	serverErrors chan error
	acceptDone   chan struct{}
	handlerWait  sync.WaitGroup
	errorOnce    sync.Once
}

func TestTLS13ClassicalEcho(t *testing.T) {
	harness := newTLSHarness(t, tls.X25519)
	t.Cleanup(func() {
		if err := harness.close(); err != nil {
			t.Errorf("close TLS harness: %v", err)
		}
	})

	if _, err := harness.roundTrip(tls.X25519); err != nil {
		t.Fatal(err)
	}
}

func TestTLS13HybridMLKEM768Echo(t *testing.T) {
	harness := newTLSHarness(t, tls.X25519MLKEM768)
	t.Cleanup(func() {
		if err := harness.close(); err != nil {
			t.Errorf("close TLS harness: %v", err)
		}
	})

	if _, err := harness.roundTrip(tls.X25519MLKEM768); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkTLS13ClassicalEcho(b *testing.B) {
	benchmarkTLS13Echo(b, tls.X25519)
}

func BenchmarkTLS13HybridMLKEM768Echo(b *testing.B) {
	benchmarkTLS13Echo(b, tls.X25519MLKEM768)
}

func benchmarkTLS13Echo(b *testing.B, curve tls.CurveID) {
	harness := newTLSHarness(b, curve)
	b.Cleanup(func() {
		if err := harness.close(); err != nil {
			b.Errorf("close TLS harness: %v", err)
		}
	})

	if _, err := harness.roundTrip(curve); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := harness.roundTrip(curve); err != nil {
			b.Fatal(err)
		}
	}
}

func newTLSHarness(t testing.TB, curve tls.CurveID) *tlsHarness {
	t.Helper()

	certificate, root, err := newServerCertificate()
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}

	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{certificate},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{curve},
		SessionTicketsDisabled: true,
	}
	clientConfig := &tls.Config{
		RootCAs:                x509.NewCertPool(),
		ServerName:             "localhost",
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{curve},
		SessionTicketsDisabled: true,
	}
	clientConfig.RootCAs.AddCert(root)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS harness: %v", err)
	}

	harness := &tlsHarness{
		listener:     listener,
		address:      listener.Addr().String(),
		serverConfig: serverConfig,
		clientConfig: clientConfig,
		serverErrors: make(chan error, 1),
		acceptDone:   make(chan struct{}),
	}
	go harness.acceptConnections()
	return harness
}

func (h *tlsHarness) acceptConnections() {
	defer close(h.acceptDone)
	for {
		connection, err := h.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			h.reportError(fmt.Errorf("accept TLS connection: %w", err))
			return
		}

		h.handlerWait.Add(1)
		go h.handleConnection(connection)
	}
}

func (h *tlsHarness) handleConnection(connection net.Conn) {
	defer h.handlerWait.Done()
	defer connection.Close()

	tlsConnection := tls.Server(connection, h.serverConfig)
	defer tlsConnection.Close()
	if err := tlsConnection.Handshake(); err != nil {
		h.reportError(fmt.Errorf("server TLS handshake: %w", err))
		return
	}

	request := make([]byte, tlsPayloadBytes)
	if _, err := io.ReadFull(tlsConnection, request); err != nil {
		h.reportError(fmt.Errorf("read TLS echo request: %w", err))
		return
	}
	if !bytes.Equal(request, tlsPayload()) {
		h.reportError(errors.New("TLS echo request did not match the expected payload"))
		return
	}
	if err := writeAll(tlsConnection, request); err != nil {
		h.reportError(fmt.Errorf("write TLS echo response: %w", err))
	}
}

func (h *tlsHarness) roundTrip(expectedCurve tls.CurveID) (tls.ConnectionState, error) {
	connection, err := tls.Dial("tcp", h.address, h.clientConfig)
	if err != nil {
		return tls.ConnectionState{}, h.withServerError(fmt.Errorf("dial TLS %s: %w", expectedCurve, err))
	}
	defer connection.Close()

	state := connection.ConnectionState()
	if err := verifyConnectionState(state, expectedCurve); err != nil {
		return state, err
	}

	request := tlsPayload()
	if err := writeAll(connection, request); err != nil {
		return state, fmt.Errorf("write TLS %s request: %w", expectedCurve, err)
	}
	response := make([]byte, len(request))
	if _, err := io.ReadFull(connection, response); err != nil {
		return state, fmt.Errorf("read TLS %s response: %w", expectedCurve, err)
	}
	if !bytes.Equal(request, response) {
		return state, fmt.Errorf("TLS %s echo response did not match the request", expectedCurve)
	}
	if err := h.serverError(); err != nil {
		return state, err
	}
	return state, nil
}

func (h *tlsHarness) close() error {
	if err := h.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	<-h.acceptDone
	h.handlerWait.Wait()
	return h.serverError()
}

func (h *tlsHarness) reportError(err error) {
	h.errorOnce.Do(func() {
		h.serverErrors <- err
	})
}

func (h *tlsHarness) serverError() error {
	select {
	case err := <-h.serverErrors:
		return err
	default:
		return nil
	}
}

func (h *tlsHarness) withServerError(err error) error {
	if serverErr := h.serverError(); serverErr != nil {
		return serverErr
	}
	return err
}

func verifyConnectionState(state tls.ConnectionState, expectedCurve tls.CurveID) error {
	if !state.HandshakeComplete {
		return errors.New("TLS handshake did not complete")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("expected TLS 1.3, got %s", tls.VersionName(state.Version))
	}
	if state.DidResume {
		return errors.New("TLS connection unexpectedly resumed")
	}
	if state.CurveID != expectedCurve {
		return fmt.Errorf("expected TLS curve %s, got %s", expectedCurve, state.CurveID)
	}
	if state.CipherSuite == 0 {
		return errors.New("TLS connection negotiated no cipher suite")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("TLS connection received no peer certificate")
	}
	publicKey, ok := state.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("TLS connection received a non-ECDSA P-256 certificate")
	}
	return nil
}

func newServerCertificate() (tls.Certificate, *x509.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: parsed}, parsed, nil
}

func tlsPayload() []byte {
	payload := make([]byte, tlsPayloadBytes)
	for index := range payload {
		payload[index] = byte(index % 255)
	}
	return payload
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
