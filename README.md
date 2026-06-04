# Post Quantum .NET Benchmarks

This repository contains two console apps:

- The root app in [Program.cs](Program.cs) benchmarks raw ML-KEM and classical ECDH operations.
- The localhost TLS 1.3 app in [TlsE2eBenchmark/Program.cs](TlsE2eBenchmark/Program.cs) benchmarks full client/server handshakes over `SslStream`.

The devcontainer installs OpenSSL 3.5.0 in [`.devcontainer/install-openssl-3.5.sh`](.devcontainer/install-openssl-3.5.sh) so the ML-KEM and ML-DSA scenarios can run on Linux.

## Prerequisites

- .NET 10 SDK
- OpenSSL 3.5.0 or newer on Linux
- The devcontainer already handles the OpenSSL dependency during post-create

## One-command benchmark run

Run the full benchmark suite with:

```bash
bash ./run-benchmarks.sh
```

That script does all of the following:

- Runs the root console benchmark in Release mode.
- Runs the localhost TLS benchmark for both classical and post-quantum scenarios in Release mode.
- Writes the raw outputs and a summary report into `artifacts/`.
- Prints a grouped console chart so the relative average times are easy to compare.

## Run the console benchmark directly

```bash
dotnet run -c Release
```

This measures the raw crypto operations:

- ML-KEM ML-KEM-768
- ECDH P-256

## Run the TLS benchmark directly

```bash
dotnet run -c Release --project TlsE2eBenchmark -- --scenario all --iterations 100
```

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

## What the numbers mean

The console benchmark is a lower-level crypto comparison. It measures key exchange and derived-secret work without socket setup.

The TLS benchmark is end to end. It includes localhost networking, `SslStream` handshake setup, certificate validation, and the encrypted echo round trip.

That makes the TLS numbers more representative of a real application, while the console benchmark is still useful for isolating crypto cost.

If you see the same cipher suite in both the classical and PQ runs, that is not a sign the benchmark is broken. TLS 1.3 keeps the record-layer cipher suite separate from the handshake key exchange, so both scenarios can legitimately use the same suite while still exercising different handshake groups.

## Notes

- On Linux, post-quantum support depends on the native OpenSSL version, not just the .NET SDK.
- The PQ TLS scenario forces `MLKEM768` through a per-process OpenSSL config file.
- The benchmark runner stores generated reports under `artifacts/`, which is ignored by git.