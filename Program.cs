using System.Security.Cryptography;
using System.Diagnostics;

if (!MLKem.IsSupported)
{
    Console.WriteLine("ML-KEM isn't supported :(");
    return;
}

MLKemAlgorithm alg = MLKemAlgorithm.MLKem768;
const int iterations = 100;

Stopwatch stopwatch = Stopwatch.StartNew();
int matches = 0;

for (int i = 0; i < iterations; i++)
{
    using MLKem privateKey = MLKem.GenerateKey(alg);
    using MLKem publicKey = MLKem.ImportEncapsulationKey(alg, privateKey.ExportEncapsulationKey());
    publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret1);
    byte[] sharedSecret2 = privateKey.Decapsulate(ciphertext);

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
        Console.WriteLine($"MLKEM768 seed: {Convert.ToHexString(privateKey.ExportPrivateSeed())}");
        Console.WriteLine("You just got the one in 2^165 failure. There's probably a prize for that.");
        Console.WriteLine($"Round-trip {i + 1} failed.");
    }
}

stopwatch.Stop();
Console.WriteLine($"ML-KEM {alg.Name} benchmark: {matches}/{iterations} successful round-trips in {stopwatch.Elapsed.TotalMilliseconds:N2} ms");