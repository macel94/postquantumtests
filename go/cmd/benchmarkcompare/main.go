package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const schemaVersion = 2

var goBenchmarks = map[string]string{
	"BenchmarkMLKEM768RoundTrip":       "raw_mlkem768",
	"BenchmarkECDHP256RoundTrip":       "raw_ecdh_p256",
	"BenchmarkTLS13ClassicalEcho":      "tls_classical",
	"BenchmarkTLS13HybridMLKEM768Echo": "tls_post_quantum",
}

type support struct {
	RawMLKEM768               bool `json:"raw_mlkem768"`
	TLSPostQuantumKeyExchange bool `json:"tls_post_quantum_key_exchange"`
	TLSX25519MLKEM768         bool `json:"tls_x25519_mlkem768,omitempty"`
	PQCertificate             bool `json:"pq_certificate"`
}

type result struct {
	MedianMS              *float64 `json:"median_ms,omitempty"`
	AverageMS             *float64 `json:"average_ms,omitempty"`
	SamplesMS             []float64 `json:"samples_ms,omitempty"`
	SampleCount           int      `json:"sample_count,omitempty"`
	RelativeStdDevPercent *float64 `json:"relative_stddev_percent,omitempty"`
	Iterations            int      `json:"iterations"`
	Status                string   `json:"status"`
	Workload              string   `json:"workload,omitempty"`
	Protocol              string   `json:"protocol,omitempty"`
	CipherSuite           string   `json:"cipher_suite,omitempty"`
	KeyExchangeGroup      string   `json:"key_exchange_group,omitempty"`
	CertificateAlgorithm  string   `json:"certificate_algorithm,omitempty"`
	CertificateValidation string   `json:"certificate_validation,omitempty"`
}

type record struct {
	SchemaVersion       int                    `json:"schema_version"`
	GeneratedAtUTC      string                 `json:"generated_at_utc"`
	Implementation      string                 `json:"implementation"`
	Runtime             string                 `json:"runtime"`
	RuntimeChannel      string                 `json:"runtime_channel"`
	OpenSSLVersion      *string                `json:"openssl_version"`
	OpenSSLBackend      string                 `json:"openssl_backend"`
	OpenSSLLibrary       string                 `json:"openssl_library,omitempty"`
	RunElapsedMS         float64                `json:"run_elapsed_ms,omitempty"`
	PostQuantumSupport  support                `json:"post_quantum_support"`
	NegotiationEvidence map[string]string      `json:"negotiation_evidence,omitempty"`
	Console             map[string]interface{} `json:"console,omitempty"`
	TLS                 map[string]interface{} `json:"tls,omitempty"`
	Results             map[string]result      `json:"results"`
}

type benchmarkMeasurement struct {
	Iterations  int
	Nanoseconds float64
}

var goBenchmarkPattern = regexp.MustCompile(`^(Benchmark[A-Za-z0-9]+)(-[0-9]+)?[[:space:]]+([0-9]+)[[:space:]]+([0-9]+(\.[0-9]+)?)[[:space:]]+ns/op([[:space:]]|$)`)
var averagePattern = regexp.MustCompile(`Average: ([0-9.]+) ms/handshake`)
var supportPattern = regexp.MustCompile(`ML-KEM MLKEM-768 support: (supported|unsupported)`)
var roundTripPattern = regexp.MustCompile(`(\d+)/(\d+) successful round-trips in ([0-9.]+) ms`)
var lineValuePattern = regexp.MustCompile(`(?m)^  ([^:]+): ([^\r\n]+)$`)

const tlsWorkload = "tls13-loopback-fresh-connection-32-byte-echo"
const rawWorkload = "fresh-client-reused-server-raw-shared-secret"

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("expected command: go, dotnet, or merge"))
	}

	var err error
	switch os.Args[1] {
	case "go":
		err = runGo(os.Args[2:])
	case "dotnet":
		err = runDotnet(os.Args[2:])
	case "merge":
		err = runMerge(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func runGo(args []string) error {
	flags := flag.NewFlagSet("go", flag.ContinueOnError)
	input := flags.String("input", "", "Go benchmark output")
	output := flags.String("output", "", "comparison record output")
	runtime := flags.String("runtime", "", "Go runtime version")
	runElapsedMS := flags.Float64("run-elapsed-ms", 0, "whole benchmark command duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" || *runtime == "" {
		return errors.New("go requires --input, --output, and --runtime")
	}

	measurements, err := parseGoBenchmarks(*input)
	if err != nil {
		return err
	}
	average := func(name string) *float64 {
		value := measurements[name].Nanoseconds / 1_000_000
		return &value
	}
	recordValue := record{
		SchemaVersion:  schemaVersion,
		GeneratedAtUTC: nowUTC(),
		Implementation: "go",
		Runtime:        *runtime,
		RuntimeChannel: "latest-stable",
		OpenSSLVersion: nil,
		OpenSSLBackend: "standard-library",
		RunElapsedMS:   *runElapsedMS,
		PostQuantumSupport: support{
			RawMLKEM768:       true,
			TLSX25519MLKEM768: true,
			PQCertificate:     false,
		},
		NegotiationEvidence: map[string]string{
			"tls_key_exchange_group_source": "tls.ConnectionState.CurveID",
		},
		Results: map[string]result{
			"raw_mlkem768":  {AverageMS: average("raw_mlkem768"), Iterations: measurements["raw_mlkem768"].Iterations, Status: "pass"},
			"raw_ecdh_p256": {AverageMS: average("raw_ecdh_p256"), Iterations: measurements["raw_ecdh_p256"].Iterations, Status: "pass"},
			"tls_classical": {
				AverageMS: average("tls_classical"), Iterations: measurements["tls_classical"].Iterations, Status: "pass",
				Protocol: "TLS 1.3", KeyExchangeGroup: "X25519", CertificateAlgorithm: "ECDSA P-256",
			},
			"tls_post_quantum": {
				AverageMS: average("tls_post_quantum"), Iterations: measurements["tls_post_quantum"].Iterations, Status: "pass",
				Protocol: "TLS 1.3", KeyExchangeGroup: "X25519MLKEM768", CertificateAlgorithm: "ECDSA P-256",
			},
		},
	}
	return writeJSON(*output, recordValue)
}

func runDotnet(args []string) error {
	flags := flag.NewFlagSet("dotnet", flag.ContinueOnError)
	consolePath := flags.String("console", "", ".NET raw benchmark output")
	tlsPath := flags.String("tls", "", ".NET TLS benchmark output")
	markdownPath := flags.String("markdown", "", "summary Markdown output")
	jsonPath := flags.String("json", "", "summary JSON output")
	runtime := flags.String("runtime", "", ".NET target framework")
	runtimeChannel := flags.String("runtime-channel", "unknown", ".NET release channel")
	opensslVersion := flags.String("openssl-version", "", "OpenSSL version")
	startedNS := flags.Int64("started-ns", 0, "benchmark start timestamp")
	finishedNS := flags.Int64("finished-ns", 0, "benchmark finish timestamp")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *consolePath == "" || *tlsPath == "" || *markdownPath == "" || *jsonPath == "" || *runtime == "" {
		return errors.New("dotnet requires console, tls, markdown, json, and runtime arguments")
	}

	consoleText, err := readText(*consolePath)
	if err != nil {
		return err
	}
	tlsText, err := readText(*tlsPath)
	if err != nil {
		return err
	}
	mlkemMatch := supportPattern.FindStringSubmatch(consoleText)
	if len(mlkemMatch) != 2 {
		return errors.New("could not find ML-KEM support in .NET output")
	}
	mlkemSupported := mlkemMatch[1] == "supported"
	var mlkemMS *float64
	if mlkemSupported {
		value, err := parseRoundTrip(consoleText, `ML-KEM ML-KEM-768 benchmark:`)
		if err != nil {
			return err
		}
		mlkemMS = &value
	}
	ecdhMS, err := parseRoundTrip(consoleText, `ECDH P-256 benchmark:`)
	if err != nil {
		return err
	}
	classical, err := parseTLSScenario(tlsText, "classical")
	if err != nil {
		return err
	}
	pq, err := parseOptionalTLSScenario(tlsText, "pq")
	if err != nil {
		return err
	}
	tlsPQSupported := pq != nil && strings.Contains(pq.KeyExchangeGroup, "MLKEM768")
	pqCertificateSupported := pq != nil && strings.HasPrefix(pq.CertificateAlgorithm, "ML-DSA")

	tlsDetails := map[string]interface{}{
		"classical_ms_per_handshake":      classical.AverageMS,
		"classical_cipher_suite":          classical.CipherSuite,
		"classical_key_exchange_group":    classical.KeyExchangeGroup,
		"classical_certificate_algorithm": classical.CertificateAlgorithm,
	}
	tlsPQResult := result{Status: status(pq != nil)}
	if pq != nil {
		tlsDetails["post_quantum_ms_per_handshake"] = pq.AverageMS
		tlsDetails["post_quantum_cipher_suite"] = pq.CipherSuite
		tlsDetails["post_quantum_key_exchange_group"] = pq.KeyExchangeGroup
		tlsDetails["post_quantum_certificate_algorithm"] = pq.CertificateAlgorithm
		tlsPQResult = result{
			AverageMS:            &pq.AverageMS,
			Iterations:           pq.Iterations,
			Status:               "pass",
			Protocol:             pq.Protocol,
			CipherSuite:          pq.CipherSuite,
			KeyExchangeGroup:     pq.KeyExchangeGroup,
			CertificateAlgorithm: pq.CertificateAlgorithm,
		}
	}

	var openssl *string
	if *opensslVersion != "" {
		openssl = opensslVersion
	}
	elapsedMS := float64(0)
	if *startedNS != 0 && *finishedNS >= *startedNS {
		elapsedMS = float64(*finishedNS-*startedNS) / 1_000_000
	}
	recordValue := record{
		SchemaVersion:  schemaVersion,
		GeneratedAtUTC: nowUTC(),
		Implementation: "dotnet",
		Runtime:        *runtime,
		RuntimeChannel: *runtimeChannel,
		OpenSSLVersion: openssl,
		OpenSSLBackend: "system-openssl",
		RunElapsedMS:   elapsedMS,
		PostQuantumSupport: support{
			RawMLKEM768:       mlkemSupported,
				TLSX25519MLKEM768: tlsPQSupported,
				PQCertificate:     pqCertificateSupported,
		},
		NegotiationEvidence: map[string]string{
			"tls_key_exchange_group_source": "restricted OpenSSL configuration via OPENSSL_CONF; SslStream does not expose the named group directly",
		},
		Console: map[string]interface{}{
			"mlkem768_ms_per_round_trip":  mlkemMS,
			"ecdh_p256_ms_per_round_trip": ecdhMS,
		},
		TLS: tlsDetails,
		Results: map[string]result{
			"raw_mlkem768":  {AverageMS: mlkemMS, Iterations: 100, Status: status(mlkemSupported)},
			"raw_ecdh_p256": {AverageMS: &ecdhMS, Iterations: 100, Status: "pass"},
			"tls_classical": {
				AverageMS: &classical.AverageMS, Iterations: classical.Iterations, Status: "pass",
				Protocol: classical.Protocol, CipherSuite: classical.CipherSuite, KeyExchangeGroup: classical.KeyExchangeGroup, CertificateAlgorithm: classical.CertificateAlgorithm,
			},
			"tls_post_quantum": tlsPQResult,
		},
	}
	if err := writeJSON(*jsonPath, recordValue); err != nil {
		return err
	}
	return writeDotnetMarkdown(*markdownPath, recordValue)
}

func parseOptionalTLSScenario(text, scenario string) (*tlsMeasurement, error) {
	if !strings.Contains(text, "Running "+scenario+" scenario...") {
		return nil, nil
	}
	measurement, err := parseTLSScenario(text, scenario)
	if err != nil {
		return nil, err
	}
	return &measurement, nil
}

type tlsMeasurement struct {
	AverageMS            float64
	Iterations           int
	Protocol             string
	CipherSuite          string
	KeyExchangeGroup     string
	CertificateAlgorithm string
}

func parseTLSScenario(text, scenario string) (tlsMeasurement, error) {
	startMarker := "Running " + scenario + " scenario..."
	start := strings.Index(text, startMarker)
	if start < 0 {
		return tlsMeasurement{}, fmt.Errorf("could not find TLS %s scenario", scenario)
	}
	section := text[start:]
	if next := strings.Index(section[len(startMarker):], "\nRunning "); next >= 0 {
		section = section[:len(startMarker)+next]
	}
	average, err := captureFloat(averagePattern, section, "TLS "+scenario+" average")
	if err != nil {
		return tlsMeasurement{}, err
	}
	iterations, err := captureInt(regexp.MustCompile(`(\d+) handshakes in`), section, "TLS "+scenario+" iterations")
	if err != nil {
		return tlsMeasurement{}, err
	}
	values := map[string]string{}
	for _, match := range lineValuePattern.FindAllStringSubmatch(section, -1) {
		values[match[1]] = strings.TrimSpace(match[2])
	}
	for _, key := range []string{"Protocol", "Cipher suite", "TLS key exchange group", "Server certificate"} {
		if values[key] == "" {
			return tlsMeasurement{}, fmt.Errorf("could not find %s in TLS %s scenario", key, scenario)
		}
	}
	return tlsMeasurement{
		AverageMS: average, Iterations: iterations, Protocol: values["Protocol"],
		CipherSuite:      values["Cipher suite"],
		KeyExchangeGroup: values["TLS key exchange group"], CertificateAlgorithm: values["Server certificate"],
	}, nil
}

func parseRoundTrip(text, marker string) (float64, error) {
	start := strings.Index(text, marker)
	if start < 0 {
		return 0, fmt.Errorf("could not find %s", marker)
	}
	match := roundTripPattern.FindStringSubmatch(text[start:])
	if len(match) != 4 {
		return 0, fmt.Errorf("could not parse %s", marker)
	}
	completed, err := strconv.Atoi(match[1])
	if err != nil || completed == 0 {
		return 0, fmt.Errorf("invalid completed count for %s", marker)
	}
	totalMS, err := strconv.ParseFloat(match[3], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid elapsed time for %s: %w", marker, err)
	}
	return totalMS / float64(completed), nil
}

func parseGoBenchmarks(path string) (map[string]benchmarkMeasurement, error) {
	text, err := readText(path)
	if err != nil {
		return nil, err
	}
	measurements := make(map[string]benchmarkMeasurement)
	for _, line := range strings.Split(text, "\n") {
		match := goBenchmarkPattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 7 {
			continue
		}
		name, ok := goBenchmarks[match[1]]
		if !ok {
			continue
		}
		if _, exists := measurements[name]; exists {
			return nil, fmt.Errorf("duplicate Go benchmark result: %s", name)
		}
		iterations, err := strconv.Atoi(match[3])
		if err != nil {
			return nil, fmt.Errorf("invalid Go iteration count: %w", err)
		}
		nanoseconds, err := strconv.ParseFloat(match[4], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid Go ns/op: %w", err)
		}
		measurements[name] = benchmarkMeasurement{Iterations: iterations, Nanoseconds: nanoseconds}
	}
	for _, name := range goBenchmarks {
		if _, ok := measurements[name]; !ok {
			return nil, fmt.Errorf("missing Go benchmark result: %s", name)
		}
	}
	return measurements, nil
}

func runMerge(args []string) error {
	flags := flag.NewFlagSet("merge", flag.ContinueOnError)
	inputDir := flags.String("input-dir", "", "directory containing records")
	outputDir := flags.String("output-dir", "", "comparison report directory")
	requireComplete := flags.Bool("require-complete", false, "require Go plus every .NET/OpenSSL matrix leg")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inputDir == "" || *outputDir == "" {
		return errors.New("merge requires --input-dir and --output-dir")
	}
	records, err := loadRecords(*inputDir)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("no comparison records found under %s", *inputDir)
	}
	if err := validateRecords(records, *requireComplete); err != nil {
		return err
	}
	sort.Slice(records, func(i, j int) bool { return recordKey(records[i]) < recordKey(records[j]) })
	comparison := struct {
		SchemaVersion  int      `json:"schema_version"`
		GeneratedAtUTC string   `json:"generated_at_utc"`
		Records        []record `json:"records"`
	}{schemaVersion, nowUTC(), records}
	if err := writeJSON(filepath.Join(*outputDir, "comparison.json"), comparison); err != nil {
		return err
	}
	markdown := renderMarkdown(records)
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*outputDir, "comparison.md"), []byte(markdown), 0o644)
}

func loadRecords(root string) ([]record, error) {
	var records []record
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".json" || filepath.Base(path) == "comparison.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var candidate record
		if err := json.Unmarshal(data, &candidate); err != nil || candidate.SchemaVersion != schemaVersion || candidate.Implementation == "" || len(candidate.Results) == 0 {
			return nil
		}
		records = append(records, candidate)
		return nil
	})
	return records, err
}

func validateRecords(records []record, requireComplete bool) error {
	seen := make(map[string]bool)
	for _, item := range records {
		key := recordKey(item)
		if seen[key] {
			return fmt.Errorf("duplicate comparison record: %s", key)
		}
		seen[key] = true
	}
	if !requireComplete {
		return nil
	}
	expected := map[string]bool{
		"go|go-stable|":        true,
		"dotnet|net10.0|3.5.0": true,
		"dotnet|net10.0|4.0.0": true,
		"dotnet|net11.0|3.5.0": true,
		"dotnet|net11.0|4.0.0": true,
	}
	actual := make(map[string]bool)
	for _, item := range records {
		if item.Implementation == "go" {
			actual["go|go-stable|"] = true
		} else {
			actual[recordKey(item)] = true
		}
	}
	var missing []string
	for key := range expected {
		if !actual[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing comparison records: %s", strings.Join(missing, ", "))
	}
	return nil
}

func renderMarkdown(records []record) string {
	var builder strings.Builder
	builder.WriteString("# Cross-language benchmark comparison\n\n")
	builder.WriteString("This report compares the Go latest-stable baseline with .NET 10 and .NET 11 preview.\n")
	builder.WriteString("Go uses the standard library and does not link to OpenSSL; its single baseline is independent of the .NET OpenSSL 3.5/4.0 matrix.\n\n")
	builder.WriteString("## Results\n\n")
	builder.WriteString("| Runtime | OpenSSL | Run ms | Raw ML-KEM ms | Raw ECDH ms | TLS classical ms | TLS PQ ms | PQ support |\n")
	builder.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |\n")
	ordered := append([]record(nil), records...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Implementation != right.Implementation {
			return left.Implementation == "go"
		}
		return recordKey(left) < recordKey(right)
	})
	for _, item := range ordered {
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			displayRuntime(item), displayOpenSSL(item), number(item.RunElapsedMS),
			numberResult(item, "raw_mlkem768"), numberResult(item, "raw_ecdh_p256"),
			numberResult(item, "tls_classical"), numberResult(item, "tls_post_quantum"), supportLabel(item)))
	}
	builder.WriteString("\n## Negotiated results\n\n")
	builder.WriteString("| Runtime | OpenSSL | Classical group | PQ group | Cipher suite | PQ certificate |\n")
	builder.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, item := range ordered {
		classical := item.Results["tls_classical"]
		pq := item.Results["tls_post_quantum"]
		certificate := "no"
		if item.PostQuantumSupport.PQCertificate {
			certificate = "yes"
		}
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n", displayRuntime(item), displayOpenSSL(item), classical.KeyExchangeGroup, pq.KeyExchangeGroup, displayValue(pq.CipherSuite), certificate))
	}
	builder.WriteString("\n`Run ms` is the whole benchmark command duration, including setup and both raw/TLS benchmark phases. The per-operation columns are the measured averages reported by each implementation.\n")
	return builder.String()
}

func writeDotnetMarkdown(path string, item record) error {
	consoleMLKEM := item.Results["raw_mlkem768"].AverageMS
	ecdh := item.Results["raw_ecdh_p256"].AverageMS
	classical := item.Results["tls_classical"].AverageMS
	pq := item.Results["tls_post_quantum"].AverageMS
	ratio := "n/a"
	if consoleMLKEM != nil && ecdh != nil && *ecdh != 0 {
		ratio = fmt.Sprintf("%.2fx", *consoleMLKEM / *ecdh)
	}
	tlsRatio := "n/a"
	if classical != nil && pq != nil && *classical != 0 {
		tlsRatio = fmt.Sprintf("%.2fx", *pq / *classical)
	}
	content := fmt.Sprintf("# Benchmark Summary\n\n| Area | Algorithm | Avg ms |\n| --- | --- | ---: |\n| Console | ML-KEM-768 | %s |\n| Console | ECDH P-256 | %s |\n| TLS 1.3 | Classical | %s |\n| TLS 1.3 | Post-quantum | %s |\n\n## Relative slowdown\n\n- Console PQ vs classical: %s\n- TLS PQ vs classical: %s\n- Whole benchmark run: %.2f ms\n- PQ support: raw ML-KEM-768 %s; TLS hybrid %s; PQ certificate %s\n",
		pointerNumber(consoleMLKEM), pointerNumber(ecdh), pointerNumber(classical), pointerNumber(pq), ratio, tlsRatio, item.RunElapsedMS,
		yesNo(item.PostQuantumSupport.RawMLKEM768), yesNo(item.PostQuantumSupport.TLSX25519MLKEM768), yesNo(item.PostQuantumSupport.PQCertificate))
	return os.WriteFile(path, []byte(content), 0o644)
}

func recordKey(item record) string {
	openssl := ""
	if item.OpenSSLVersion != nil {
		openssl = *item.OpenSSLVersion
	}
	return item.Implementation + "|" + item.Runtime + "|" + openssl
}

func displayRuntime(item record) string {
	if item.Implementation == "go" {
		return "Go (" + item.Runtime + ")"
	}
	if item.Runtime == "net11.0" {
		return ".NET 11 preview"
	}
	if item.Runtime == "net10.0" {
		return ".NET 10"
	}
	return ".NET " + item.Runtime
}

func displayOpenSSL(item record) string {
	if item.OpenSSLVersion == nil {
		return "Not used"
	}
	return *item.OpenSSLVersion
}

func supportLabel(item record) string {
	if item.PostQuantumSupport.RawMLKEM768 && item.PostQuantumSupport.TLSX25519MLKEM768 {
		return "yes"
	}
	if !item.PostQuantumSupport.RawMLKEM768 && !item.PostQuantumSupport.TLSX25519MLKEM768 {
		return "no"
	}
	return "partial"
}

func number(value float64) string { return fmt.Sprintf("%.2f", value) }

func numberResult(item record, name string) string {
	return pointerNumber(item.Results[name].AverageMS)
}

func pointerNumber(value *float64) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", *value)
}

func displayValue(value string) string {
	if value == "" {
		return "n/a"
	}
	return value
}

func status(supported bool) string {
	if supported {
		return "pass"
	}
	return "unsupported"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func captureFloat(pattern *regexp.Regexp, text, label string) (float64, error) {
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0, fmt.Errorf("could not find %s", label)
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", label, err)
	}
	return value, nil
}

func captureInt(pattern *regexp.Regexp, text, label string) (int, error) {
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0, fmt.Errorf("could not find %s", label)
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", label, err)
	}
	return value, nil
}

func readText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return string(data), nil
}

func writeJSON(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func resultFromSamples(samples []float64, iterations int, status string) (result, error) {
	if len(samples) == 0 {
		return result{}, errors.New("missing benchmark samples")
	}
	ordered := append([]float64(nil), samples...)
	sort.Float64s(ordered)
	median := ordered[len(ordered)/2]
	if len(ordered)%2 == 0 {
		median = (ordered[len(ordered)/2-1] + ordered[len(ordered)/2]) / 2
	}
	var relative *float64
	if len(samples) > 1 {
		mean := 0.0
		for _, sample := range samples {
			mean += sample
		}
		mean /= float64(len(samples))
		if mean != 0 {
			variance := 0.0
			for _, sample := range samples {
				difference := sample - mean
				variance += difference * difference
			}
			value := math.Sqrt(variance/float64(len(samples)-1)) / mean * 100
			relative = &value
		}
	}
	return result{MedianMS: &median, SamplesMS: samples, SampleCount: len(samples), RelativeStdDevPercent: relative, Iterations: iterations, Status: status}, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "benchmark comparison failed: %v\n", err)
	os.Exit(1)
}
