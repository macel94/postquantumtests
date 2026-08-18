using System.Security.Cryptography;
using System.Diagnostics;

bool mlkemSupported = MLKem.IsSupported;
Console.WriteLine($"ML-KEM MLKEM-768 support: {(mlkemSupported ? "supported" : "unsupported")}");

int iterations = ParseIterations(args);
string scenario = ParseScenario(args);

if (scenario != "ecdh" && mlkemSupported)
{
    MLKemAlgorithm alg = MLKemAlgorithm.MLKem768;
    using MLKem mlkemServerKey = MLKem.GenerateKey(alg);
    byte[] mlkemServerPublicKey = mlkemServerKey.ExportEncapsulationKey();

    Stopwatch stopwatch = Stopwatch.StartNew();
    int matches = 0;

    for (int i = 0; i < iterations; i++)
    {
        using MLKem publicKey = MLKem.ImportEncapsulationKey(alg, mlkemServerPublicKey);
        publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret1);
        byte[] sharedSecret2 = mlkemServerKey.Decapsulate(ciphertext);

        if (sharedSecret1.AsSpan().SequenceEqual(sharedSecret2))
        {
            matches++;
#if DEBUG
            Console.WriteLine($"Round-trip {i + 1} successful. Same answer: {Convert.ToHexString(sharedSecret1)}");
#endif
        }
        else
        {
            Console.WriteLine($"Round-trip {i + 1} failed. Different answers:");
            Console.WriteLine($"sharedSecret1: {Convert.ToHexString(sharedSecret1)}");
            Console.WriteLine($"sharedSecret2: {Convert.ToHexString(sharedSecret2)}");
            Console.WriteLine($"MLKEM768 seed: {Convert.ToHexString(mlkemServerKey.ExportPrivateSeed())}");
            Console.WriteLine("You just got the one in 2^165 failure. There's probably a prize for that.");
            Console.WriteLine($"Round-trip {i + 1} failed.");
        }
    }

    stopwatch.Stop();
    Console.WriteLine($"ML-KEM {alg.Name} benchmark: {matches}/{iterations} successful round-trips in {stopwatch.Elapsed.TotalMilliseconds:N2} ms");
}

if (scenario != "mlkem")
{
    using ECDiffieHellman ecdhServerKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    Stopwatch ecdhStopwatch = Stopwatch.StartNew();
    int ecdhMatches = 0;

    for (int i = 0; i < iterations; i++)
    {
        using ECDiffieHellman clientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] handshakeSecret1 = clientKey.DeriveRawSecretAgreement(ecdhServerKey.PublicKey);
        byte[] handshakeSecret2 = ecdhServerKey.DeriveRawSecretAgreement(clientKey.PublicKey);

        if (handshakeSecret1.AsSpan().SequenceEqual(handshakeSecret2))
        {
            ecdhMatches++;
        }
    }

    ecdhStopwatch.Stop();
    Console.WriteLine($"ECDH P-256 benchmark: {ecdhMatches}/{iterations} successful round-trips in {ecdhStopwatch.Elapsed.TotalMilliseconds:N2} ms");
}

static int ParseIterations(string[] args)
{
    for (int index = 0; index < args.Length; index++)
    {
        if (args[index] != "--iterations" || index + 1 >= args.Length || !int.TryParse(args[index + 1], out int iterations) || iterations <= 0)
        {
            continue;
        }

        return iterations;
    }

    return 100;
}

static string ParseScenario(string[] args)
{
    for (int index = 0; index < args.Length; index++)
    {
        if (args[index] != "--scenario")
        {
            continue;
        }

        if (index + 1 >= args.Length)
        {
            throw new ArgumentException("--scenario requires all, mlkem, or ecdh.");
        }

        return args[index + 1].ToLowerInvariant() switch
        {
            "all" or "mlkem" or "ecdh" => args[index + 1].ToLowerInvariant(),
            _ => throw new ArgumentException("--scenario requires all, mlkem, or ecdh."),
        };
    }

    return "all";
}