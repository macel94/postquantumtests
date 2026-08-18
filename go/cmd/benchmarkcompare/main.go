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

const schemaVersion = 4

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
}

type result struct {
	MedianMS              *float64  `json:"median_ms,omitempty"`
	AverageMS             *float64  `json:"average_ms,omitempty"`
	SamplesMS             []float64 `json:"samples_ms,omitempty"`
	SampleCount           int       `json:"sample_count,omitempty"`
	RelativeStdDevPercent *float64  `json:"relative_stddev_percent,omitempty"`
	Iterations            int       `json:"iterations"`
	Status                string    `json:"status"`
	Workload              string    `json:"workload,omitempty"`
	Protocol              string    `json:"protocol,omitempty"`
	CipherSuite           string    `json:"cipher_suite,omitempty"`
	KeyExchangeGroup      string    `json:"key_exchange_group,omitempty"`
	CertificateAlgorithm  string    `json:"certificate_algorithm,omitempty"`
	CertificateValidation string    `json:"certificate_validation,omitempty"`
}

type record struct {
	SchemaVersion       int                    `json:"schema_version"`
	GeneratedAtUTC      string                 `json:"generated_at_utc"`
	Implementation      string                 `json:"implementation"`
	Runtime             string                 `json:"runtime"`
	RuntimeChannel      string                 `json:"runtime_channel"`
	OpenSSLVersion      *string                `json:"openssl_version"`
	OpenSSLBackend      string                 `json:"openssl_backend"`
	OpenSSLLibrary      string                 `json:"openssl_library,omitempty"`
	BenchmarkElapsedMS  float64                `json:"benchmark_elapsed_ms,omitempty"`
	CleanBuildMS        float64                `json:"clean_build_ms,omitempty"`
	CachedBuildMS       float64                `json:"cached_build_ms,omitempty"`
	PostQuantumSupport  support                `json:"post_quantum_support"`
	NegotiationEvidence map[string]string      `json:"negotiation_evidence,omitempty"`
	Console             map[string]interface{} `json:"console,omitempty"`
	TLS                 map[string]interface{} `json:"tls,omitempty"`
	Results             map[string]result      `json:"results"`
}

type benchmarkMeasurement struct {
	Iterations         int
	SamplesNanoseconds []float64
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
	benchmarkElapsedMS := flags.Float64("benchmark-elapsed-ms", 0, "prebuilt benchmark execution duration")
	cleanBuildMS := flags.Float64("clean-build-ms", 0, "clean build duration for both benchmark targets")
	cachedBuildMS := flags.Float64("cached-build-ms", 0, "cached build duration for both benchmark targets")
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
	benchmarkResult := func(name string) (result, error) {
		measurement := measurements[name]
		samples := make([]float64, len(measurement.SamplesNanoseconds))
		for index, nanoseconds := range measurement.SamplesNanoseconds {
			samples[index] = nanoseconds / 1_000_000
		}
		return resultFromSamples(samples, measurement.Iterations, "pass")
	}
	results := make(map[string]result, len(measurements))
	for _, name := range goBenchmarks {
		results[name], err = benchmarkResult(name)
		if err != nil {
			return err
		}
	}
	classicalResult := results["tls_classical"]
	classicalResult.Protocol = "TLS 1.3"
	classicalResult.KeyExchangeGroup = "X25519"
	classicalResult.CertificateAlgorithm = "ECDSA P-256"
	results["tls_classical"] = classicalResult
	pqResult := results["tls_post_quantum"]
	pqResult.Protocol = "TLS 1.3"
	pqResult.KeyExchangeGroup = "X25519MLKEM768"
	pqResult.CertificateAlgorithm = "ECDSA P-256"
	results["tls_post_quantum"] = pqResult
	recordValue := record{
		SchemaVersion:      schemaVersion,
		GeneratedAtUTC:     nowUTC(),
		Implementation:     "go",
		Runtime:            *runtime,
		RuntimeChannel:     "latest-stable",
		OpenSSLVersion:     nil,
		OpenSSLBackend:     "standard-library",
		BenchmarkElapsedMS: *benchmarkElapsedMS,
		CleanBuildMS:       *cleanBuildMS,
		CachedBuildMS:      *cachedBuildMS,
		PostQuantumSupport: support{
			RawMLKEM768:       true,
			TLSX25519MLKEM768: true,
		},
		NegotiationEvidence: map[string]string{
			"tls_key_exchange_group_source": "tls.ConnectionState.CurveID",
		},
		Results: results,
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
	benchmarkElapsedMS := flags.Float64("benchmark-elapsed-ms", 0, "prebuilt benchmark execution duration")
	cleanBuildMS := flags.Float64("clean-build-ms", 0, "clean build duration for both benchmark targets")
	cachedBuildMS := flags.Float64("cached-build-ms", 0, "cached build duration for both benchmark targets")
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
	mlkemResult := result{Status: status(mlkemSupported)}
	if mlkemSupported {
		samples, iterations, err := parseRoundTrip(consoleText, `ML-KEM ML-KEM-768 benchmark:`)
		if err != nil {
			return err
		}
		mlkemResult, err = resultFromSamples(samples, iterations, "pass")
		if err != nil {
			return err
		}
	}
	ecdhSamples, ecdhIterations, err := parseRoundTrip(consoleText, `ECDH P-256 benchmark:`)
	if err != nil {
		return err
	}
	ecdhResult, err := resultFromSamples(ecdhSamples, ecdhIterations, "pass")
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
	if err := validateTLSPair(classical, pq); err != nil {
		return err
	}
	tlsPQSupported := pq != nil && strings.HasPrefix(pq.KeyExchangeGroup, "X25519MLKEM768")

	tlsDetails := map[string]interface{}{
		"classical_ms_per_handshake":      classical.MedianMS,
		"classical_cipher_suite":          classical.CipherSuite,
		"classical_key_exchange_group":    classical.KeyExchangeGroup,
		"classical_certificate_algorithm": classical.CertificateAlgorithm,
	}
	tlsPQResult := result{Status: status(pq != nil)}
	if pq != nil {
		tlsDetails["post_quantum_ms_per_handshake"] = pq.MedianMS
		tlsDetails["post_quantum_cipher_suite"] = pq.CipherSuite
		tlsDetails["post_quantum_key_exchange_group"] = pq.KeyExchangeGroup
		tlsDetails["post_quantum_certificate_algorithm"] = pq.CertificateAlgorithm
		tlsPQResult, err = resultFromSamples(pq.SamplesMS, pq.Iterations, "pass")
		if err != nil {
			return err
		}
		tlsPQResult.Protocol = pq.Protocol
		tlsPQResult.CipherSuite = pq.CipherSuite
		tlsPQResult.KeyExchangeGroup = pq.KeyExchangeGroup
		tlsPQResult.CertificateAlgorithm = pq.CertificateAlgorithm
	}

	var openssl *string
	if *opensslVersion != "" {
		openssl = opensslVersion
	}
	recordValue := record{
		SchemaVersion:      schemaVersion,
		GeneratedAtUTC:     nowUTC(),
		Implementation:     "dotnet",
		Runtime:            *runtime,
		RuntimeChannel:     *runtimeChannel,
		OpenSSLVersion:     openssl,
		OpenSSLBackend:     "system-openssl",
		BenchmarkElapsedMS: *benchmarkElapsedMS,
		CleanBuildMS:       *cleanBuildMS,
		CachedBuildMS:      *cachedBuildMS,
		PostQuantumSupport: support{
			RawMLKEM768:       mlkemSupported,
			TLSX25519MLKEM768: tlsPQSupported,
		},
		NegotiationEvidence: map[string]string{
			"tls_key_exchange_group_source": "OpenSSL TLS-group preflight plus a single-group OPENSSL_CONF restriction; SslStream does not expose the named group directly",
		},
		Console: map[string]interface{}{
			"mlkem768_ms_per_round_trip":  mlkemResult.MedianMS,
			"ecdh_p256_ms_per_round_trip": ecdhResult.MedianMS,
		},
		TLS: tlsDetails,
		Results: map[string]result{
			"raw_mlkem768":  mlkemResult,
			"raw_ecdh_p256": ecdhResult,
			"tls_classical": {
				MedianMS: &classical.MedianMS, SamplesMS: classical.SamplesMS, SampleCount: len(classical.SamplesMS), RelativeStdDevPercent: classical.RelativeStdDevPercent, Iterations: classical.Iterations, Status: "pass",
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
	MedianMS              float64
	SamplesMS             []float64
	RelativeStdDevPercent *float64
	Iterations            int
	Protocol              string
	CipherSuite           string
	KeyExchangeGroup      string
	CertificateAlgorithm  string
}

func parseTLSScenario(text, scenario string) (tlsMeasurement, error) {
	sections := tlsScenarioSections(text, scenario)
	if len(sections) == 0 {
		return tlsMeasurement{}, fmt.Errorf("could not find TLS %s scenario", scenario)
	}
	var samples []float64
	var measurement tlsMeasurement
	for index, section := range sections {
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
		current := tlsMeasurement{
			Iterations: iterations, Protocol: normalizeTLSProtocol(values["Protocol"]),
			CipherSuite: values["Cipher suite"], KeyExchangeGroup: normalizeTLSGroup(values["TLS key exchange group"]),
			CertificateAlgorithm: normalizeCertificateAlgorithm(values["Server certificate"]),
		}
		if index == 0 {
			measurement = current
		} else if current.Iterations != measurement.Iterations || current.Protocol != measurement.Protocol || current.CipherSuite != measurement.CipherSuite || current.KeyExchangeGroup != measurement.KeyExchangeGroup || current.CertificateAlgorithm != measurement.CertificateAlgorithm {
			return tlsMeasurement{}, fmt.Errorf("TLS %s samples reported inconsistent metadata", scenario)
		}
		samples = append(samples, average)
	}
	aggregated, err := resultFromSamples(samples, measurement.Iterations, "pass")
	if err != nil {
		return tlsMeasurement{}, err
	}
	measurement.MedianMS = *aggregated.MedianMS
	measurement.SamplesMS = aggregated.SamplesMS
	measurement.RelativeStdDevPercent = aggregated.RelativeStdDevPercent
	return measurement, nil
}

func tlsScenarioSections(text, scenario string) []string {
	marker := "Running " + scenario + " scenario..."
	var sections []string
	searchFrom := 0
	for searchFrom < len(text) {
		relativeStart := strings.Index(text[searchFrom:], marker)
		if relativeStart < 0 {
			break
		}
		start := searchFrom + relativeStart
		end := len(text)
		if relativeEnd := strings.Index(text[start+len(marker):], "\nRunning "); relativeEnd >= 0 {
			end = start + len(marker) + relativeEnd + 1
		}
		sections = append(sections, text[start:end])
		searchFrom = end
	}
	return sections
}

func validateTLSPair(classical tlsMeasurement, pq *tlsMeasurement) error {
	if err := validateTLSMeasurement(classical, "classical"); err != nil {
		return err
	}
	if pq == nil {
		return nil
	}
	if err := validateTLSMeasurement(*pq, "post-quantum"); err != nil {
		return err
	}
	if classical.Protocol != pq.Protocol {
		return fmt.Errorf("TLS scenarios used different protocols: %s versus %s", classical.Protocol, pq.Protocol)
	}
	if classical.CertificateAlgorithm != pq.CertificateAlgorithm {
		return fmt.Errorf("TLS scenarios used different certificate algorithms: %s versus %s", classical.CertificateAlgorithm, pq.CertificateAlgorithm)
	}
	if classical.KeyExchangeGroup != "X25519" {
		return fmt.Errorf("classical TLS scenario used unexpected key exchange group: %s", classical.KeyExchangeGroup)
	}
	if pq.KeyExchangeGroup != "X25519MLKEM768" {
		return fmt.Errorf("post-quantum TLS scenario did not use hybrid X25519MLKEM768: %s", pq.KeyExchangeGroup)
	}
	return nil
}

func validateTLSMeasurement(measurement tlsMeasurement, scenario string) error {
	if measurement.Protocol != "TLS 1.3" {
		return fmt.Errorf("%s TLS scenario used unexpected protocol: %s", scenario, measurement.Protocol)
	}
	if measurement.CipherSuite == "" {
		return fmt.Errorf("%s TLS scenario did not report a cipher suite", scenario)
	}
	if measurement.CertificateAlgorithm != "ECDSA P-256" {
		return fmt.Errorf("%s TLS scenario used unexpected certificate algorithm: %s", scenario, measurement.CertificateAlgorithm)
	}
	return nil
}

func normalizeTLSGroup(value string) string {
	if suffix := strings.Index(value, " ("); suffix >= 0 {
		return value[:suffix]
	}
	return value
}

func normalizeTLSProtocol(value string) string {
	if value == "Tls13" {
		return "TLS 1.3"
	}
	return value
}

func normalizeCertificateAlgorithm(value string) string {
	if strings.HasPrefix(value, "ECDSA") && strings.Contains(value, "256") {
		return "ECDSA P-256"
	}
	return value
}

func parseRoundTrip(text, marker string) ([]float64, int, error) {
	var samples []float64
	iterations := 0
	searchFrom := 0
	for searchFrom < len(text) {
		relativeStart := strings.Index(text[searchFrom:], marker)
		if relativeStart < 0 {
			break
		}
		start := searchFrom + relativeStart
		end := len(text)
		for _, otherMarker := range []string{`ML-KEM ML-KEM-768 benchmark:`, `ECDH P-256 benchmark:`} {
			if relativeEnd := strings.Index(text[start+len(marker):], otherMarker); relativeEnd >= 0 && start+len(marker)+relativeEnd < end {
				end = start + len(marker) + relativeEnd
			}
		}
		match := roundTripPattern.FindStringSubmatch(text[start:end])
		if len(match) != 4 {
			return nil, 0, fmt.Errorf("could not parse %s", marker)
		}
		completed, err := strconv.Atoi(match[1])
		if err != nil || completed == 0 {
			return nil, 0, fmt.Errorf("invalid completed count for %s", marker)
		}
		currentIterations, err := strconv.Atoi(match[2])
		if err != nil || currentIterations == 0 {
			return nil, 0, fmt.Errorf("invalid iteration count for %s", marker)
		}
		if completed != currentIterations {
			return nil, 0, fmt.Errorf("incomplete round-trip sample for %s: %d/%d", marker, completed, currentIterations)
		}
		if iterations == 0 {
			iterations = currentIterations
		} else if iterations != currentIterations {
			return nil, 0, fmt.Errorf("inconsistent iteration count for %s", marker)
		}
		totalMS, err := strconv.ParseFloat(match[3], 64)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid elapsed time for %s: %w", marker, err)
		}
		samples = append(samples, totalMS/float64(completed))
		searchFrom = start + len(marker)
	}
	if len(samples) == 0 {
		return nil, 0, fmt.Errorf("could not find %s", marker)
	}
	return samples, iterations, nil
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
		iterations, err := strconv.Atoi(match[3])
		if err != nil {
			return nil, fmt.Errorf("invalid Go iteration count: %w", err)
		}
		nanoseconds, err := strconv.ParseFloat(match[4], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid Go ns/op: %w", err)
		}
		measurement := measurements[name]
		if measurement.Iterations != 0 && measurement.Iterations != iterations {
			return nil, fmt.Errorf("inconsistent Go iteration count for %s", name)
		}
		measurement.Iterations = iterations
		measurement.SamplesNanoseconds = append(measurement.SamplesNanoseconds, nanoseconds)
		measurements[name] = measurement
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
		if item.BenchmarkElapsedMS <= 0 || item.CleanBuildMS <= 0 || item.CachedBuildMS <= 0 {
			return fmt.Errorf("incomplete comparable timing metrics: %s", recordKey(item))
		}
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
	builder.WriteString("| Runtime | OpenSSL | Benchmark ms | Clean build ms | Cached build ms | Raw ML-KEM ms | Raw ECDH ms | TLS classical ms | TLS PQ ms | PQ support |\n")
	builder.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n")
	ordered := append([]record(nil), records...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := ordered[i], ordered[j]
		if left.Implementation != right.Implementation {
			return left.Implementation == "go"
		}
		return recordKey(left) < recordKey(right)
	})
	for _, item := range ordered {
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			displayRuntime(item), displayOpenSSL(item), number(item.BenchmarkElapsedMS), number(item.CleanBuildMS), number(item.CachedBuildMS),
			numberResult(item, "raw_mlkem768"), numberResult(item, "raw_ecdh_p256"),
			numberResult(item, "tls_classical"), numberResult(item, "tls_post_quantum"), supportLabel(item)))
	}
	builder.WriteString("\n## Negotiated results\n\n")
	builder.WriteString("| Runtime | OpenSSL | Classical group | PQ group | Classical cipher | PQ cipher | Classical certificate | PQ certificate |\n")
	builder.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, item := range ordered {
		classical := item.Results["tls_classical"]
		pq := item.Results["tls_post_quantum"]
		builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n", displayRuntime(item), displayOpenSSL(item), classical.KeyExchangeGroup, pq.KeyExchangeGroup, displayValue(classical.CipherSuite), displayValue(pq.CipherSuite), displayValue(classical.CertificateAlgorithm), displayValue(pq.CertificateAlgorithm)))
	}
	builder.WriteString("\n`Benchmark ms` covers only prebuilt raw/TLS benchmark execution. `Clean build ms` and `Cached build ms` cover the same two benchmark targets for each implementation and exclude benchmark execution. The per-operation columns are the medians across five measured samples; each result retains its sample count and relative standard deviation in JSON.\n")
	return builder.String()
}

func writeDotnetMarkdown(path string, item record) error {
	consoleMLKEM := item.Results["raw_mlkem768"].MedianMS
	ecdh := item.Results["raw_ecdh_p256"].MedianMS
	classical := item.Results["tls_classical"].MedianMS
	pq := item.Results["tls_post_quantum"].MedianMS
	ratio := "n/a"
	if consoleMLKEM != nil && ecdh != nil && *ecdh != 0 {
		ratio = fmt.Sprintf("%.2fx", *consoleMLKEM / *ecdh)
	}
	tlsRatio := "n/a"
	if classical != nil && pq != nil && *classical != 0 {
		tlsRatio = fmt.Sprintf("%.2fx", *pq / *classical)
	}
	content := fmt.Sprintf("# Benchmark Summary\n\n| Area | Algorithm | Median ms |\n| --- | --- | ---: |\n| Console | ML-KEM-768 | %s |\n| Console | ECDH P-256 | %s |\n| TLS 1.3 | Classical | %s |\n| TLS 1.3 | Post-quantum | %s |\n\n## Relative slowdown\n\n- Console PQ vs classical: %s\n- TLS PQ vs classical: %s\n- Prebuilt benchmark phase: %.2f ms\n- Clean build (two targets): %.2f ms\n- Cached build (two targets): %.2f ms\n- PQ support: raw ML-KEM-768 %s; TLS hybrid X25519MLKEM768 %s\n",
		pointerNumber(consoleMLKEM), pointerNumber(ecdh), pointerNumber(classical), pointerNumber(pq), ratio, tlsRatio, item.BenchmarkElapsedMS, item.CleanBuildMS, item.CachedBuildMS,
		yesNo(item.PostQuantumSupport.RawMLKEM768), yesNo(item.PostQuantumSupport.TLSX25519MLKEM768))
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
	return pointerNumber(item.Results[name].MedianMS)
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
