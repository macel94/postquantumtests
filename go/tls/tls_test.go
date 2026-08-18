package tlsbenchmark

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tlsPayloadBytes = 32

const (
	tlsServerProcessEnv     = "POSTQUANTUM_TLS_SERVER_PROCESS"
	tlsServerCertificateEnv = "POSTQUANTUM_TLS_SERVER_CERTIFICATE"
	tlsServerPrivateKeyEnv  = "POSTQUANTUM_TLS_SERVER_PRIVATE_KEY"
	tlsServerCurveEnv       = "POSTQUANTUM_TLS_SERVER_CURVE"
	tlsServerReadyPrefix    = "POSTQUANTUM_TLS_SERVER_READY "
)

type tlsHarness struct {
	address       string
	clientConfig  *tls.Config
	serverProcess *exec.Cmd
	serverWait    <-chan error
	serverStderr  *bytes.Buffer
}

func TestTLS13ClassicalEcho(t *testing.T) {
	if os.Getenv(tlsServerProcessEnv) == "1" {
		runTLSServerProcess(t)
		return
	}

	harness := newTLSHarness(t, tls.X25519)
	t.Cleanup(func() {
		if err := harness.close(); err != nil {
			t.Errorf("close TLS harness: %v", err)
		}
	})

	state, err := harness.roundTrip(tls.X25519, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyConnectionState(state, tls.X25519); err != nil {
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

	state, err := harness.roundTrip(tls.X25519MLKEM768, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyConnectionState(state, tls.X25519MLKEM768); err != nil {
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

	state, err := harness.roundTrip(curve, true)
	if err != nil {
		b.Fatal(err)
	}
	if err := verifyConnectionState(state, curve); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := harness.roundTrip(curve, false); err != nil {
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

	clientConfig := &tls.Config{
		RootCAs:                x509.NewCertPool(),
		ServerName:             "localhost",
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{curve},
		SessionTicketsDisabled: true,
	}
	clientConfig.RootCAs.AddCert(root)

	serverProcess, address, serverWait, serverStderr, err := startTLSServerProcess(certificate, curve)
	if err != nil {
		t.Fatalf("start TLS server process: %v", err)
	}

	return &tlsHarness{
		address:       address,
		clientConfig:  clientConfig,
		serverProcess: serverProcess,
		serverWait:    serverWait,
		serverStderr:  serverStderr,
	}
}

func handleTLSConnection(connection net.Conn, serverConfig *tls.Config) error {
	defer connection.Close()

	tlsConnection := tls.Server(connection, serverConfig)
	defer tlsConnection.Close()
	if err := tlsConnection.Handshake(); err != nil {
		return fmt.Errorf("server TLS handshake: %w", err)
	}

	request := make([]byte, tlsPayloadBytes)
	if _, err := io.ReadFull(tlsConnection, request); err != nil {
		return fmt.Errorf("read TLS echo request: %w", err)
	}
	if !bytes.Equal(request, tlsPayload()) {
		return errors.New("TLS echo request did not match the expected payload")
	}
	if err := writeAll(tlsConnection, request); err != nil {
		return fmt.Errorf("write TLS echo response: %w", err)
	}
	return nil
}

func (h *tlsHarness) roundTrip(expectedCurve tls.CurveID, captureState bool) (tls.ConnectionState, error) {
	connection, err := tls.Dial("tcp", h.address, h.clientConfig)
	if err != nil {
		return tls.ConnectionState{}, fmt.Errorf("dial TLS %s: %w", expectedCurve, err)
	}
	defer connection.Close()

	state := tls.ConnectionState{}
	if captureState {
		state = connection.ConnectionState()
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
	return state, nil
}

func (h *tlsHarness) close() error {
	killErr := h.serverProcess.Process.Kill()
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return killErr
	}
	if err := <-h.serverWait; err != nil && errors.Is(killErr, os.ErrProcessDone) {
		return fmt.Errorf("TLS server process: %w: %s", err, h.serverStderr.String())
	}
	return nil
}

func startTLSServerProcess(certificate tls.Certificate, curve tls.CurveID) (*exec.Cmd, string, <-chan error, *bytes.Buffer, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return nil, "", nil, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})

	command := exec.Command(os.Args[0], "-test.run", "^TestTLS13ClassicalEcho$", "-test.v")
	command.Env = append(os.Environ(),
		tlsServerProcessEnv+"=1",
		tlsServerCertificateEnv+"="+base64.StdEncoding.EncodeToString(certificatePEM),
		tlsServerPrivateKeyEnv+"="+base64.StdEncoding.EncodeToString(privateKeyPEM),
		tlsServerCurveEnv+"="+strconv.FormatUint(uint64(curve), 10),
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, "", nil, nil, err
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, "", nil, nil, err
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if address, ok := strings.CutPrefix(scanner.Text(), tlsServerReadyPrefix); ok {
			wait := make(chan error, 1)
			go func() {
				wait <- command.Wait()
			}()
			return command, address, wait, stderr, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", nil, nil, err
	}
	if err := command.Wait(); err != nil {
		return nil, "", nil, nil, fmt.Errorf("TLS server process exited before readiness: %w: %s", err, stderr.String())
	}
	return nil, "", nil, nil, errors.New("TLS server process exited before readiness")
}

func runTLSServerProcess(t *testing.T) {
	certificatePEM, err := base64.StdEncoding.DecodeString(os.Getenv(tlsServerCertificateEnv))
	if err != nil {
		t.Fatalf("decode server certificate: %v", err)
	}
	privateKeyPEM, err := base64.StdEncoding.DecodeString(os.Getenv(tlsServerPrivateKeyEnv))
	if err != nil {
		t.Fatalf("decode server private key: %v", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	curveValue, err := strconv.ParseUint(os.Getenv(tlsServerCurveEnv), 10, 16)
	if err != nil {
		t.Fatalf("parse server curve: %v", err)
	}
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{certificate},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.CurveID(curveValue)},
		SessionTicketsDisabled: true,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for TLS server process: %v", err)
	}
	defer listener.Close()
	fmt.Printf("%s%s\n", tlsServerReadyPrefix, listener.Addr())

	for {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatalf("accept TLS connection: %v", err)
		}
		if err := handleTLSConnection(connection, serverConfig); err != nil {
			t.Fatal(err)
		}
	}
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
