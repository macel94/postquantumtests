# Post-Quantum TLS Benchmarks

This repository compares post-quantum and classical key exchange costs in .NET and Go.

- [dotnet/raw-kem/Program.cs](dotnet/raw-kem/Program.cs) measures raw ML-KEM-768 and ECDH P-256 round trips.
- [dotnet/tls/Program.cs](dotnet/tls/Program.cs) measures localhost TLS 1.3 handshakes and an encrypted echo over `SslStream`.
- [go/raw_test.go](go/raw_test.go) measures the same raw ML-KEM-768 and ECDH P-256 operations with the Go standard library.
- [go/tls_test.go](go/tls_test.go) measures Go TLS 1.3 with X25519 and hybrid X25519+ML-KEM-768 key exchange.

## Requirements

- Linux
- .NET 10 SDK, or the .NET 11 preview SDK for `net11.0` runs
- Go 1.26 or newer
- Python 3 for the .NET report-producing runner
- OpenSSL 3.5.0 or 4.0.0 for the .NET TLS post-quantum scenario

The Go tests use only the standard library. They do not require OpenSSL.

## Repository layout

```text
dotnet/
  raw-kem/             Raw ML-KEM and ECDH executable
  tls/                 .NET TLS 1.3 benchmark executable
  run-benchmarks.sh    .NET report-producing runner
go/
  raw_test.go          Raw ML-KEM and ECDH tests and benchmarks
  tls_test.go          TLS 1.3 tests and benchmarks
.devcontainer/
  net10-openssl35/     .NET 10 with OpenSSL 3.5
  net10-openssl40/     .NET 10 with OpenSSL 4.0
  net11-openssl35/     .NET 11 preview with OpenSSL 3.5
  net11-openssl40/     .NET 11 preview with OpenSSL 4.0
```

## Workflows

The CI surface is split into independent workflows with one purpose each:

| Workflow | Purpose | Trigger |
| --- | --- | --- |
| [OpenSSL Toolchain Cache](.github/workflows/openssl-toolchains.yml) | Build and warm the shared OpenSSL 3.5/4.0 caches | Manual or weekly |
| [.NET 10 Benchmarks](.github/workflows/dotnet10-benchmarks.yml) | Run .NET 10 against OpenSSL 3.5 and 4.0 | Push when `dotnet/**` changes or manual |
| [.NET 11 Preview Benchmarks](.github/workflows/dotnet11-preview-benchmarks.yml) | Run .NET 11 preview against OpenSSL 3.5 and 4.0 | Push when `dotnet/**` changes or manual |
| [Go Tests and Benchmarks](.github/workflows/go-tests-and-benchmarks.yml) | Run Go tests, vet, race checks, and benchmarks | Push, pull request, or manual |

The OpenSSL toolchain workflow builds each version once and stores the installed prefix in the GitHub Actions cache. The .NET workflows use the same versioned cache key. On a cache hit, [install-openssl.sh](.devcontainer/install-openssl.sh) only restores the loader configuration and verifies the exact version instead of compiling OpenSSL again.

The OpenSSL 3.5/4.0 matrix applies to the .NET TLS benchmarks. The Go tests use the standard-library `crypto/tls`, `crypto/mlkem`, and `crypto/ecdh` packages and do not link to the system OpenSSL library, so changing the installed OpenSSL version would not change the Go implementation. A Go/OpenSSL matrix would require adding a cgo binding or another OpenSSL-backed TLS implementation.

## Run the .NET benchmarks

From the repository root:

```bash
bash dotnet/run-benchmarks.sh
```

The runner defaults to `net10.0`. Select the .NET 11 preview explicitly:

```bash
DOTNET_TARGET_FRAMEWORK=net11.0 bash dotnet/run-benchmarks.sh
```

The runner restores both projects for the selected target framework, runs the raw crypto and TLS benchmarks, and writes reports under `dotnet/artifacts/`.

Run the raw benchmark directly:

```bash
dotnet run -c Release --framework net10.0 --project dotnet/raw-kem/postquantumdotnettest.csproj
```

For .NET 11 preview, restore the selected target first and then disable implicit restore:

```bash
dotnet restore dotnet/raw-kem/postquantumdotnettest.csproj -p:TargetFramework=net11.0
dotnet run --no-restore -c Release --framework net11.0 --project dotnet/raw-kem/postquantumdotnettest.csproj
```

Run the TLS benchmark directly:

```bash
dotnet run -c Release --framework net10.0 --project dotnet/tls/TlsE2eBenchmark.csproj -- --scenario all --iterations 100
```

Use the same explicit restore pattern for the .NET 11 TLS benchmark:

```bash
dotnet restore dotnet/tls/TlsE2eBenchmark.csproj -p:TargetFramework=net11.0
dotnet run --no-restore -c Release --framework net11.0 --project dotnet/tls/TlsE2eBenchmark.csproj -- --scenario all --iterations 100
```

Available TLS options are `--scenario classical|pq|all`, `--iterations N`, `--warmup N`, and `--payload-bytes N`.

The .NET TLS benchmark reports the TLS version, record-protection cipher suite, certificate algorithm, and negotiated key-exchange group. In TLS 1.3, the cipher suite is independent of the key-exchange group, so the negotiated group is the important classical/PQ comparison.

## Run the Go tests and benchmarks

```bash
cd go
go test ./...
go test -race ./...
go vet ./...
go test -bench . -benchmem -benchtime=100x ./...
```

The raw Go tests use ML-KEM-768 and ECDH P-256. The TLS tests create a local ECDSA P-256 certificate, disable resumption, force TLS 1.3, and assert the negotiated curve and echo payload. The PQ TLS benchmark uses Go's standard-library hybrid `X25519MLKEM768` group.

## Devcontainers

The default [devcontainer.json](.devcontainer/devcontainer.json) provides Go 1.26, .NET 10, and Python 3 without compiling OpenSSL. Use one of the specialized containers when working on the .NET/OpenSSL matrix:

| Devcontainer | Environment |
| --- | --- |
| [net10-openssl35](.devcontainer/net10-openssl35/devcontainer.json) | .NET 10 / OpenSSL 3.5 |
| [net10-openssl40](.devcontainer/net10-openssl40/devcontainer.json) | .NET 10 / OpenSSL 4.0 |
| [net11-openssl35](.devcontainer/net11-openssl35/devcontainer.json) | .NET 11 preview / OpenSSL 3.5 |
| [net11-openssl40](.devcontainer/net11-openssl40/devcontainer.json) | .NET 11 preview / OpenSSL 4.0 |

The specialized containers mount a persistent Docker volume for their OpenSSL version. Recreating a container therefore reuses the installed toolchain instead of compiling it again.

To install a version manually:

```bash
bash .devcontainer/install-openssl.sh 3.5.0
```

## Interpreting results

The raw benchmarks isolate cryptographic operations. The TLS benchmarks include TCP setup, certificate verification, TLS handshake, encrypted echo, and connection close for each operation.

The .NET and Go raw ML-KEM-768 results are directly comparable at the algorithm level. Their PQ TLS scenarios are related but not identical: .NET uses its OpenSSL-backed ML-KEM-768 and ML-DSA certificate configuration, while Go's standard library currently exposes hybrid X25519+ML-KEM-768 key exchange and uses an ECDSA certificate. Compare each language's classical/PQ delta within its own workflow.

## Dependency updates

[Dependabot](.github/dependabot.yml) checks GitHub Actions and Devcontainer Features weekly. The Go module has no third-party dependencies, and the .NET projects have no NuGet package references.