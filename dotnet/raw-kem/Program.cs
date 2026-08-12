using System.Security.Cryptography;
using System.Diagnostics;

if (!MLKem.IsSupported)
{
    Console.WriteLine("ML-KEM isn't supported :(");
    return;
}

MLKemAlgorithm alg = MLKemAlgorithm.MLKem768;
const int iterations = 100;

using MLKem mlkemServerKey = MLKem.GenerateKey(alg);
byte[] mlkemServerPublicKey = mlkemServerKey.ExportEncapsulationKey();

Stopwatch stopwatch = Stopwatch.StartNew();
int matches = 0;

for (int i = 0; i < iterations; i++)
{
    using MLKem publicKey = MLKem.ImportEncapsulationKey(alg, mlkemServerPublicKey);
    publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret1);
    byte[] sharedSecret2 = mlkemServerKey.Decapsulate(ciphertext);
    byte[] handshakeSecret1 = SHA256.HashData(sharedSecret1);
    byte[] handshakeSecret2 = SHA256.HashData(sharedSecret2);

    if (handshakeSecret1.AsSpan().SequenceEqual(handshakeSecret2))
    {
        matches++;
#if DEBUG
        Console.WriteLine($"Round-trip {i + 1} successful. Same answer: {Convert.ToHexString(handshakeSecret1)}");
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

using ECDiffieHellman ecdhServerKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

Stopwatch ecdhStopwatch = Stopwatch.StartNew();
int ecdhMatches = 0;

for (int i = 0; i < iterations; i++)
{
    using ECDiffieHellman clientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    byte[] handshakeSecret1 = clientKey.DeriveKeyFromHash(ecdhServerKey.PublicKey, HashAlgorithmName.SHA256);
    byte[] handshakeSecret2 = ecdhServerKey.DeriveKeyFromHash(clientKey.PublicKey, HashAlgorithmName.SHA256);

    if (handshakeSecret1.AsSpan().SequenceEqual(handshakeSecret2))
    {
        ecdhMatches++;
    }
}

ecdhStopwatch.Stop();
Console.WriteLine($"ECDH P-256 benchmark: {ecdhMatches}/{iterations} successful round-trips in {ecdhStopwatch.Elapsed.TotalMilliseconds:N2} ms");