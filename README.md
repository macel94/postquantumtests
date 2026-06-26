# Post Quantum .NET Benchmarks

This repository contains two console apps:

- The root app in [Program.cs](Program.cs) benchmarks raw ML-KEM and classical ECDH operations.
- The localhost TLS 1.3 app in [TlsE2eBenchmark/Program.cs](TlsE2eBenchmark/Program.cs) benchmarks full client/server handshakes over `SslStream`.

The default devcontainer matches the .NET 10 / OpenSSL 3.5 CI job. Additional devcontainers under [.devcontainer](.devcontainer) match every CI runtime combination so the benchmark jobs can be reproduced locally.

## Prerequisites

- .NET 10 SDK, or the latest .NET 11 preview SDK for `net11.0` runs
- OpenSSL 3.5.0 or newer on Linux
- The devcontainers handle the .NET SDK and OpenSSL dependencies during post-create

## CI matrix

The [OpenSSL benchmark workflow](.github/workflows/openssl-benchmarks.yml) is manual and runs four jobs:

| .NET SDK | Target framework | OpenSSL | Artifact |
| --- | --- | --- | --- |
| 10 GA | `net10.0` | 3.5.0 | `dotnet-10-openssl-3.5-benchmarks` |
| 10 GA | `net10.0` | 4.0.0 | `dotnet-10-openssl-4.0-benchmarks` |
| 11 latest preview | `net11.0` | 3.5.0 | `dotnet-11-preview-openssl-3.5-benchmarks` |
| 11 latest preview | `net11.0` | 4.0.0 | `dotnet-11-preview-openssl-4.0-benchmarks` |

The workflow installs .NET with `actions/setup-dotnet`. The .NET 11 rows use `dotnet-version: 11.0.x` with `dotnet-quality: preview`, then set `DOTNET_TARGET_FRAMEWORK=net11.0` before running the benchmarks.

OpenSSL is built from source by [.devcontainer/install-openssl.sh](.devcontainer/install-openssl.sh). The same script is used by CI and the devcontainers to avoid version drift.

## Dependabot

[Dependabot](.github/dependabot.yml) checks weekly for updates to:

- GitHub Actions used by workflows.
- Devcontainer Features used by the local reproduction containers.

This repository currently has no NuGet package references, so there is no NuGet Dependabot entry yet.

## One-command benchmark run

Run the full benchmark suite with:

```bash
bash ./run-benchmarks.sh
```

By default this runs `net10.0`. To run with the .NET 11 preview SDK, use:

```bash
DOTNET_TARGET_FRAMEWORK=net11.0 bash ./run-benchmarks.sh
```

That script does all of the following:

- Runs the root console benchmark in Release mode.
- Runs the localhost TLS benchmark for both classical and post-quantum scenarios in Release mode.
- Writes the raw outputs and a summary report into `artifacts/`.
- Prints a grouped console chart so the relative average times are easy to compare.

## Run the console benchmark directly

```bash
dotnet run -c Release --framework net10.0
```

For .NET 11 preview, replace `net10.0` with `net11.0`.

This measures the raw crypto operations:

- ML-KEM ML-KEM-768
- ECDH P-256

## Run the TLS benchmark directly

```bash
dotnet run -c Release --framework net10.0 --project TlsE2eBenchmark -- --scenario all --iterations 100
```

For .NET 11 preview, replace `net10.0` with `net11.0`.

Useful options:

- `--scenario classical` runs only the classical TLS 1.3 path.
- `--scenario pq` runs only the post-quantum TLS 1.3 path.
- `--scenario all` runs both.
- `--iterations N` changes the measured handshake count.
- `--warmup N` changes the warmup count.
- `--payload-bytes N` changes the echo payload size.

The TLS benchmark reports:

- TLS version
- Cipher suite
- Server certificate algorithm
- Configured key exchange group

The cipher suite is expected to be the same for both runs in this repo, most often `TLS_AES_256_GCM_SHA384`. In TLS 1.3, that value describes the symmetric record-protection suite, not whether the handshake used classical or post-quantum key exchange. The real comparison points here are the negotiated group and the certificate algorithm.

## Local CI reproduction with devcontainers

Open the repository in one of these devcontainers to reproduce a matching CI job locally:

| Devcontainer | CI job reproduced | Benchmark command |
| --- | --- | --- |
| [.devcontainer/devcontainer.json](.devcontainer/devcontainer.json) | .NET 10 / OpenSSL 3.5 | `bash ./run-benchmarks.sh` |
| [.devcontainer/dotnet10-openssl35/devcontainer.json](.devcontainer/dotnet10-openssl35/devcontainer.json) | .NET 10 / OpenSSL 3.5 | `bash ./run-benchmarks.sh` |
| [.devcontainer/dotnet10-openssl40/devcontainer.json](.devcontainer/dotnet10-openssl40/devcontainer.json) | .NET 10 / OpenSSL 4.0 | `bash ./run-benchmarks.sh` |
| [.devcontainer/dotnet11-openssl35/devcontainer.json](.devcontainer/dotnet11-openssl35/devcontainer.json) | .NET 11 preview / OpenSSL 3.5 | `bash ./run-benchmarks.sh` |
| [.devcontainer/dotnet11-openssl40/devcontainer.json](.devcontainer/dotnet11-openssl40/devcontainer.json) | .NET 11 preview / OpenSSL 4.0 | `bash ./run-benchmarks.sh` |

Each devcontainer sets `DOTNET_TARGET_FRAMEWORK` to the target framework used by its matching CI job. To switch between containers in VS Code, use `Dev Containers: Reopen in Container` and select the desired configuration. Rebuild the container when you want to pick up newer .NET SDK or devcontainer Feature versions.

## What the numbers mean

The console benchmark is a lower-level crypto comparison. It measures key exchange and derived-secret work without socket setup.

The TLS benchmark is end to end. It includes localhost networking, `SslStream` handshake setup, certificate validation, and the encrypted echo round trip.

That makes the TLS numbers more representative of a real application, while the console benchmark is still useful for isolating crypto cost.

If you see the same cipher suite in both the classical and PQ runs, that is not a sign the benchmark is broken. TLS 1.3 keeps the record-layer cipher suite separate from the handshake key exchange, so both scenarios can legitimately use the same suite while still exercising different handshake groups.

## Notes

- On Linux, post-quantum support depends on the native OpenSSL version, not just the .NET SDK.
- The PQ TLS scenario forces `MLKEM768` through a per-process OpenSSL config file.
- The project files default to `net10.0` so a .NET 10 SDK can restore and build the repository. CI and the .NET 11 devcontainers select `net11.0` explicitly.
- The benchmark runner stores generated reports under `artifacts/`, which is ignored by git.