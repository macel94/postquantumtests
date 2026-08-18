using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

AppOptions options;

try
{
    options = ParseArguments(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    PrintUsage();
    return 1;
}

if (options.ShowHelp)
{
    PrintUsage();
    return 0;
}

try
{
    return options.Role switch
    {
        null => await RunOrchestratorAsync(options),
        "server" => await RunServerAsync(options),
        "client" => await RunClientAsync(options),
        _ => throw new InvalidOperationException($"Unknown role '{options.Role}'.")
    };
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}

static async Task<int> RunOrchestratorAsync(AppOptions options)
{
    List<ScenarioDefinition> scenarios = GetRequestedScenarios(options.Scenario);

    if (scenarios.Any(static scenario => scenario.Name == "pq") && !IsPostQuantumTlsSupported())
    {
        if (options.Scenario == "pq")
        {
            throw new PlatformNotSupportedException("The post-quantum TLS scenario requires ML-KEM support.");
        }

        scenarios.RemoveAll(static scenario => scenario.Name == "pq");
        Console.WriteLine("Skipping pq scenario: ML-KEM is not supported on this platform.");
    }

    Console.WriteLine("TLS 1.3 localhost benchmark");
    Console.WriteLine($"Measured iterations: {options.Iterations}");
    Console.WriteLine($"Warmup iterations: {options.WarmupIterations}");
    Console.WriteLine($"Payload size: {options.PayloadBytes} bytes");

    foreach (ScenarioDefinition scenario in scenarios)
    {
        Console.WriteLine();
        Console.WriteLine($"Running {scenario.Name} scenario...");

        ClientBenchmarkResult result = await RunScenarioAsync(scenario, options);

        Console.WriteLine(result.Description);
        Console.WriteLine($"  {result.Iterations} handshakes in {result.ElapsedMilliseconds:N2} ms");
        Console.WriteLine($"  Average: {result.AverageMilliseconds:N2} ms/handshake");
        Console.WriteLine($"  Throughput: {result.HandshakesPerSecond:N2} handshakes/s");
        Console.WriteLine($"  Protocol: {result.SslProtocol}");
        Console.WriteLine($"  Cipher suite: {result.CipherSuite}");
        Console.WriteLine($"  Server certificate: {result.PresentedCertificateAlgorithm}");
        Console.WriteLine($"  TLS key exchange group: {result.ConfiguredKeyExchangeGroup}");
    }

    return 0;
}

static bool IsPostQuantumTlsSupported() => MLKem.IsSupported;

static async Task<ClientBenchmarkResult> RunScenarioAsync(ScenarioDefinition scenario, AppOptions options)
{
    string tempDirectory = Path.Combine(
        Path.GetTempPath(),
        "postquantumdotnettest",
        "tls-bench",
        $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{scenario.Name}-{Guid.NewGuid():N}");

    Directory.CreateDirectory(tempDirectory);

    try
    {
        using X509Certificate2 serverCertificate = CreateServerCertificate(scenario);

        string certificatePassword = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        string certificatePath = Path.Combine(tempDirectory, "server.pfx");
        string trustedCertificatePath = Path.Combine(tempDirectory, "server.cer");
        string opensslConfigPath = WriteOpenSslConfig(tempDirectory, scenario.OpenSslGroups);
        int port = GetFreeTcpPort();

        File.WriteAllBytes(certificatePath, serverCertificate.Export(X509ContentType.Pkcs12, certificatePassword));
        File.WriteAllBytes(trustedCertificatePath, serverCertificate.Export(X509ContentType.Cert));
        VerifyOpenSslGroupAvailable(scenario.OpenSslGroups, opensslConfigPath);

        using Process serverProcess = StartRoleProcess(
            role: "server",
            options,
            scenario,
            port,
            certificatePath,
            certificatePassword,
            trustedCertificatePath,
            opensslConfigPath);

        try
        {
            await WaitForServerReadyAsync(serverProcess);

            using Process clientProcess = StartRoleProcess(
                role: "client",
                options,
                scenario,
                port,
                certificatePath,
                certificatePassword,
                trustedCertificatePath,
                opensslConfigPath);

            ClientBenchmarkResult result = await ReadClientResultAsync(clientProcess);
            ValidateNegotiation(scenario, result);
            await WaitForSuccessfulExitAsync(serverProcess, "server");
            return result;
        }
        catch
        {
            TryKill(serverProcess);
            throw;
        }
    }
    finally
    {
        TryDeleteDirectory(tempDirectory);
    }
}

static async Task<int> RunServerAsync(AppOptions options)
{
    ArgumentException.ThrowIfNullOrEmpty(options.CertificatePath);
    ArgumentException.ThrowIfNullOrEmpty(options.CertificatePassword);

    X509Certificate2 serverCertificate = X509CertificateLoader.LoadPkcs12FromFile(
        options.CertificatePath,
        options.CertificatePassword,
        X509KeyStorageFlags.EphemeralKeySet,
        Pkcs12LoaderLimits.Defaults);

    SslStreamCertificateContext certificateContext = SslStreamCertificateContext.Create(
        serverCertificate,
        new X509Certificate2Collection(),
        offline: true);

    using TcpListener listener = new(IPAddress.Loopback, options.Port);
    listener.Start();

    Console.WriteLine("READY");

    int totalConnections = options.WarmupIterations + options.Iterations;

    for (int i = 0; i < totalConnections; i++)
    {
        using TcpClient tcpClient = await listener.AcceptTcpClientAsync();
        tcpClient.NoDelay = true;

        using SslStream sslStream = new(tcpClient.GetStream(), leaveInnerStreamOpen: false);

        SslServerAuthenticationOptions authenticationOptions = new()
        {
            AllowTlsResume = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificateRequired = false,
            EnabledSslProtocols = SslProtocols.Tls13,
            ServerCertificateContext = certificateContext,
        };

        await sslStream.AuthenticateAsServerAsync(authenticationOptions);

        byte[] request = GC.AllocateUninitializedArray<byte>(options.PayloadBytes);
        await sslStream.ReadExactlyAsync(request);
        await sslStream.WriteAsync(request);
        await sslStream.FlushAsync();
    }

    return 0;
}

static async Task<int> RunClientAsync(AppOptions options)
{
    ScenarioDefinition scenario = GetScenario(options.Scenario);
    ArgumentException.ThrowIfNullOrEmpty(options.TrustedCertificatePath);

    X509Certificate2 trustedCertificate = X509CertificateLoader.LoadCertificateFromFile(options.TrustedCertificatePath);
    byte[] payload = CreatePayload(options.PayloadBytes);

    for (int i = 0; i < options.WarmupIterations; i++)
    {
        await ExecuteClientConnectionAsync(options, trustedCertificate, payload, captureMetadata: false);
    }

    NegotiationSnapshot? snapshot = null;
    Stopwatch stopwatch = Stopwatch.StartNew();

    for (int i = 0; i < options.Iterations; i++)
    {
        snapshot ??= await ExecuteClientConnectionAsync(options, trustedCertificate, payload, captureMetadata: true);

        if (snapshot is not null && i > 0)
        {
            await ExecuteClientConnectionAsync(options, trustedCertificate, payload, captureMetadata: false);
        }
    }

    stopwatch.Stop();

    snapshot ??= await ExecuteClientConnectionAsync(options, trustedCertificate, payload, captureMetadata: true);

    ClientBenchmarkResult result = new(
        Scenario: scenario.Name,
        Description: scenario.Description,
        ConfiguredKeyExchangeGroup: scenario.ConfiguredKeyExchangeGroup,
        Iterations: options.Iterations,
        WarmupIterations: options.WarmupIterations,
        PayloadBytes: options.PayloadBytes,
        ElapsedMilliseconds: stopwatch.Elapsed.TotalMilliseconds,
        AverageMilliseconds: stopwatch.Elapsed.TotalMilliseconds / options.Iterations,
        HandshakesPerSecond: options.Iterations / stopwatch.Elapsed.TotalSeconds,
        SslProtocol: snapshot.SslProtocol,
        CipherSuite: snapshot.CipherSuite,
        PresentedCertificateAlgorithm: snapshot.PresentedCertificateAlgorithm);

    Console.WriteLine("RESULT " + JsonSerializer.Serialize(result));
    return 0;
}

static async Task<NegotiationSnapshot> ExecuteClientConnectionAsync(
    AppOptions options,
    X509Certificate2 trustedCertificate,
    byte[] payload,
    bool captureMetadata)
{
    using TcpClient tcpClient = new(AddressFamily.InterNetwork);
    tcpClient.NoDelay = true;
    await tcpClient.ConnectAsync(IPAddress.Loopback, options.Port);

    using SslStream sslStream = new(
        tcpClient.GetStream(),
        leaveInnerStreamOpen: false,
        userCertificateValidationCallback: (_, certificate, _, _) => MatchesTrustedCertificate(certificate, trustedCertificate));

    SslClientAuthenticationOptions authenticationOptions = new()
    {
        AllowTlsResume = false,
        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        EnabledSslProtocols = SslProtocols.Tls13,
        TargetHost = "localhost",
    };

    await sslStream.AuthenticateAsClientAsync(authenticationOptions);
    await sslStream.WriteAsync(payload);
    await sslStream.FlushAsync();

    byte[] response = GC.AllocateUninitializedArray<byte>(payload.Length);
    await sslStream.ReadExactlyAsync(response);

    if (!payload.AsSpan().SequenceEqual(response))
    {
        throw new InvalidOperationException("The TLS echo payload did not match the request.");
    }

    if (!captureMetadata)
    {
        return new NegotiationSnapshot(string.Empty, string.Empty, string.Empty);
    }

    if (sslStream.RemoteCertificate is null)
    {
        throw new InvalidOperationException("The server did not present a certificate.");
    }

    using X509Certificate2 remoteCertificate = new(sslStream.RemoteCertificate);

    return new NegotiationSnapshot(
        sslStream.SslProtocol.ToString(),
        sslStream.NegotiatedCipherSuite.ToString(),
        DescribeCertificateAlgorithm(remoteCertificate));
}

static bool MatchesTrustedCertificate(X509Certificate? presentedCertificate, X509Certificate2 trustedCertificate)
{
    if (presentedCertificate is null)
    {
        return false;
    }

    using X509Certificate2 candidate = new(presentedCertificate);
    return candidate.RawData.AsSpan().SequenceEqual(trustedCertificate.RawData);
}

static void ValidateNegotiation(ScenarioDefinition scenario, ClientBenchmarkResult result)
{
    if (!string.Equals(result.SslProtocol, "Tls13", StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"The {scenario.Name} scenario negotiated {result.SslProtocol} instead of TLS 1.3.");
    }

    if (string.IsNullOrWhiteSpace(result.CipherSuite))
    {
        throw new InvalidOperationException($"The {scenario.Name} scenario did not report a negotiated cipher suite.");
    }

    if (!string.Equals(result.PresentedCertificateAlgorithm, "ECDSA (256-bit)", StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            $"The {scenario.Name} scenario presented {result.PresentedCertificateAlgorithm} instead of ECDSA (256-bit).");
    }

    if (!string.Equals(result.ConfiguredKeyExchangeGroup, scenario.ConfiguredKeyExchangeGroup, StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            $"The {scenario.Name} scenario reported an unexpected key exchange group: {result.ConfiguredKeyExchangeGroup}.");
    }
}

static Process StartRoleProcess(
    string role,
    AppOptions options,
    ScenarioDefinition scenario,
    int port,
    string certificatePath,
    string certificatePassword,
    string trustedCertificatePath,
    string opensslConfigPath)
{
    ProcessStartInfo startInfo = CreateSelfProcessStartInfo();

    startInfo.ArgumentList.Add("--role");
    startInfo.ArgumentList.Add(role);
    startInfo.ArgumentList.Add("--scenario");
    startInfo.ArgumentList.Add(scenario.Name);
    startInfo.ArgumentList.Add("--iterations");
    startInfo.ArgumentList.Add(options.Iterations.ToString(CultureInfo.InvariantCulture));
    startInfo.ArgumentList.Add("--warmup");
    startInfo.ArgumentList.Add(options.WarmupIterations.ToString(CultureInfo.InvariantCulture));
    startInfo.ArgumentList.Add("--payload-bytes");
    startInfo.ArgumentList.Add(options.PayloadBytes.ToString(CultureInfo.InvariantCulture));
    startInfo.ArgumentList.Add("--port");
    startInfo.ArgumentList.Add(port.ToString(CultureInfo.InvariantCulture));

    if (role == "server")
    {
        startInfo.ArgumentList.Add("--cert-path");
        startInfo.ArgumentList.Add(certificatePath);
        startInfo.ArgumentList.Add("--cert-password");
        startInfo.ArgumentList.Add(certificatePassword);
    }

    if (role == "client")
    {
        startInfo.ArgumentList.Add("--trusted-cert-path");
        startInfo.ArgumentList.Add(trustedCertificatePath);
    }

    startInfo.Environment["OPENSSL_CONF"] = opensslConfigPath;

    Process process = new() { StartInfo = startInfo };

    if (!process.Start())
    {
        throw new InvalidOperationException($"Failed to start the {role} process.");
    }

    return process;
}

static ProcessStartInfo CreateSelfProcessStartInfo()
{
    string processPath = Environment.ProcessPath
        ?? throw new InvalidOperationException("Unable to determine the current process path.");

    ProcessStartInfo startInfo = new()
    {
        FileName = processPath,
        RedirectStandardError = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };

    if (Path.GetFileName(processPath).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
    {
        string assemblyPath = Assembly.GetExecutingAssembly().Location;
        startInfo.ArgumentList.Add(assemblyPath);
    }

    return startInfo;
}

static async Task WaitForServerReadyAsync(Process process)
{
    while (true)
    {
        string? line = await process.StandardOutput.ReadLineAsync();

        if (line is null)
        {
            string errorOutput = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            throw new InvalidOperationException(
                $"The server exited before signaling readiness. Exit code: {process.ExitCode}.{Environment.NewLine}{errorOutput}");
        }

        if (line == "READY")
        {
            return;
        }
    }
}

static async Task<ClientBenchmarkResult> ReadClientResultAsync(Process process)
{
    string standardOutput = await process.StandardOutput.ReadToEndAsync();
    string errorOutput = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"The client exited with code {process.ExitCode}.{Environment.NewLine}{standardOutput}{Environment.NewLine}{errorOutput}");
    }

    string? resultLine = standardOutput
        .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
        .LastOrDefault(line => line.StartsWith("RESULT ", StringComparison.Ordinal));

    if (resultLine is null)
    {
        throw new InvalidOperationException($"The client did not emit a RESULT line.{Environment.NewLine}{standardOutput}");
    }

    ClientBenchmarkResult? result = JsonSerializer.Deserialize<ClientBenchmarkResult>(resultLine[7..]);

    if (result is null)
    {
        throw new InvalidOperationException($"Unable to parse the client benchmark result.{Environment.NewLine}{resultLine}");
    }

    return result;
}

static async Task WaitForSuccessfulExitAsync(Process process, string role)
{
    string standardOutput = await process.StandardOutput.ReadToEndAsync();
    string errorOutput = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"The {role} exited with code {process.ExitCode}.{Environment.NewLine}{standardOutput}{Environment.NewLine}{errorOutput}");
    }
}

static void TryKill(Process process)
{
    if (process.HasExited)
    {
        return;
    }

    try
    {
        process.Kill(entireProcessTree: true);
    }
    catch
    {
    }
}

static void TryDeleteDirectory(string path)
{
    if (!Directory.Exists(path))
    {
        return;
    }

    try
    {
        Directory.Delete(path, recursive: true);
    }
    catch
    {
    }
}

static List<ScenarioDefinition> GetRequestedScenarios(string scenario)
{
    if (scenario == "all")
    {
        return [GetScenario("classical"), GetScenario("pq")];
    }

    return [GetScenario(scenario)];
}

static ScenarioDefinition GetScenario(string scenario) => scenario switch
{
    "classical" => new ScenarioDefinition(
        Name: "classical",
        Description: "Classical TLS 1.3 on loopback with an ECDSA P-256 certificate and X25519 key exchange.",
        ConfiguredKeyExchangeGroup: "X25519 (forced via OPENSSL_CONF)",
        OpenSslGroups: "X25519"),
    "pq" => new ScenarioDefinition(
        Name: "pq",
        Description: "Post-quantum TLS 1.3 on loopback with an ECDSA P-256 certificate and X25519MLKEM768 hybrid key exchange.",
        ConfiguredKeyExchangeGroup: "X25519MLKEM768 (restricted via OPENSSL_CONF)",
        OpenSslGroups: "X25519MLKEM768"),
    _ => throw new ArgumentException($"Unknown scenario '{scenario}'. Expected 'classical', 'pq', or 'all'.")
};

static string WriteOpenSslConfig(string tempDirectory, string groups)
{
    string configPath = Path.Combine(tempDirectory, "openssl.cnf");
    string contents = string.Join(
        Environment.NewLine,
        ".include /etc/ssl/openssl.cnf",
        string.Empty,
        "config_diagnostics = 1",
        "openssl_conf = postquantumdotnettest_init",
        string.Empty,
        "[postquantumdotnettest_init]",
        "providers = provider_sect",
        "ssl_conf = postquantumdotnettest_ssl",
        string.Empty,
        "[postquantumdotnettest_ssl]",
        "system_default = postquantumdotnettest_tls",
        string.Empty,
        "[postquantumdotnettest_tls]",
        "MinProtocol = TLSv1.3",
        "MaxProtocol = TLSv1.3",
        $"Groups = {groups}",
        "Options = -SessionTicket",
        string.Empty);

    File.WriteAllText(configPath, contents, Encoding.ASCII);
    return configPath;
}

static void VerifyOpenSslGroupAvailable(string group, string configPath)
{
    ProcessStartInfo startInfo = new()
    {
        FileName = "openssl",
        RedirectStandardError = true,
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    startInfo.ArgumentList.Add("list");
    startInfo.ArgumentList.Add("-tls-groups");
    startInfo.Environment["OPENSSL_CONF"] = configPath;

    using Process process = Process.Start(startInfo)
        ?? throw new InvalidOperationException("Unable to start the openssl group preflight.");
    string output = process.StandardOutput.ReadToEnd();
    string errorOutput = process.StandardError.ReadToEnd();
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"The openssl group preflight failed with code {process.ExitCode}.{Environment.NewLine}{errorOutput}");
    }

    bool groupIsAvailable = output
        .Split([':', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
        .Any(candidate => string.Equals(candidate, group, StringComparison.OrdinalIgnoreCase));

    if (!groupIsAvailable)
    {
        throw new PlatformNotSupportedException(
            $"OpenSSL does not advertise the required TLS 1.3 group '{group}'.");
    }
}

static X509Certificate2 CreateServerCertificate(ScenarioDefinition scenario)
{
    DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
    DateTimeOffset notAfter = notBefore.AddDays(7);

    using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    CertificateRequest classicalRequest = new("CN=localhost", ecdsa, HashAlgorithmName.SHA256);
    AddServerCertificateExtensions(classicalRequest);
    return classicalRequest.CreateSelfSigned(notBefore, notAfter);
}

static void AddServerCertificateExtensions(CertificateRequest request)
{
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

    OidCollection enhancedKeyUsage = new()
    {
        new Oid("1.3.6.1.5.5.7.3.1"),
    };

    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(enhancedKeyUsage, critical: false));

    SubjectAlternativeNameBuilder subjectAlternativeName = new();
    subjectAlternativeName.AddDnsName("localhost");
    subjectAlternativeName.AddIpAddress(IPAddress.Loopback);
    request.CertificateExtensions.Add(subjectAlternativeName.Build());
    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
}

static byte[] CreatePayload(int size)
{
    byte[] payload = new byte[size];

    for (int i = 0; i < payload.Length; i++)
    {
        payload[i] = (byte)(i % byte.MaxValue);
    }

    return payload;
}

static string DescribeCertificateAlgorithm(X509Certificate2 certificate)
{
#pragma warning disable SYSLIB5006
    using MLDsa? mldsa = certificate.GetMLDsaPublicKey();
#pragma warning restore SYSLIB5006

    if (mldsa is not null)
    {
        return mldsa.Algorithm.Name;
    }

    using ECDsa? ecdsa = certificate.GetECDsaPublicKey();

    if (ecdsa is not null)
    {
        return $"ECDSA ({ecdsa.KeySize}-bit)";
    }

    using RSA? rsa = certificate.GetRSAPublicKey();

    if (rsa is not null)
    {
        return $"RSA ({rsa.KeySize}-bit)";
    }

    return certificate.PublicKey.Oid?.FriendlyName
        ?? certificate.PublicKey.Oid?.Value
        ?? "unknown";
}

static int GetFreeTcpPort()
{
    using TcpListener listener = new(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}

static AppOptions ParseArguments(string[] args)
{
    string? role = null;
    string scenario = "all";
    int iterations = 100;
    int warmupIterations = 5;
    int payloadBytes = 32;
    int port = 0;
    string? certificatePath = null;
    string? certificatePassword = null;
    string? trustedCertificatePath = null;
    bool showHelp = false;

    for (int i = 0; i < args.Length; i++)
    {
        string argument = args[i];

        switch (argument)
        {
            case "-h":
            case "--help":
                showHelp = true;
                break;
            case "--role":
                role = ReadValue(args, ref i, argument).ToLowerInvariant();
                break;
            case "--scenario":
                scenario = ReadValue(args, ref i, argument).ToLowerInvariant();
                break;
            case "--iterations":
                iterations = ParsePositiveInt(ReadValue(args, ref i, argument), argument, allowZero: false);
                break;
            case "--warmup":
                warmupIterations = ParsePositiveInt(ReadValue(args, ref i, argument), argument, allowZero: true);
                break;
            case "--payload-bytes":
                payloadBytes = ParsePositiveInt(ReadValue(args, ref i, argument), argument, allowZero: false);
                break;
            case "--port":
                port = ParsePositiveInt(ReadValue(args, ref i, argument), argument, allowZero: false);
                break;
            case "--cert-path":
                certificatePath = ReadValue(args, ref i, argument);
                break;
            case "--cert-password":
                certificatePassword = ReadValue(args, ref i, argument);
                break;
            case "--trusted-cert-path":
                trustedCertificatePath = ReadValue(args, ref i, argument);
                break;
            default:
                throw new ArgumentException($"Unknown argument '{argument}'.");
        }
    }

    if (role is not null && scenario == "all")
    {
        throw new ArgumentException("Child roles require a concrete --scenario value.");
    }

    if (role is "server" or "client" && port == 0)
    {
        throw new ArgumentException("Child roles require --port.");
    }

    if (role == "server" && string.IsNullOrWhiteSpace(certificatePath))
    {
        throw new ArgumentException("The server role requires --cert-path.");
    }

    if (role == "server" && string.IsNullOrWhiteSpace(certificatePassword))
    {
        throw new ArgumentException("The server role requires --cert-password.");
    }

    if (role == "client" && string.IsNullOrWhiteSpace(trustedCertificatePath))
    {
        throw new ArgumentException("The client role requires --trusted-cert-path.");
    }

    return new AppOptions(
        Role: role,
        Scenario: scenario,
        Iterations: iterations,
        WarmupIterations: warmupIterations,
        PayloadBytes: payloadBytes,
        Port: port,
        CertificatePath: certificatePath,
        CertificatePassword: certificatePassword,
        TrustedCertificatePath: trustedCertificatePath,
        ShowHelp: showHelp);
}

static string ReadValue(string[] args, ref int index, string argumentName)
{
    if (index + 1 >= args.Length)
    {
        throw new ArgumentException($"Missing value for {argumentName}.");
    }

    index++;
    return args[index];
}

static int ParsePositiveInt(string value, string argumentName, bool allowZero)
{
    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int parsedValue))
    {
        throw new ArgumentException($"The value '{value}' for {argumentName} is not a valid integer.");
    }

    if (allowZero && parsedValue < 0)
    {
        throw new ArgumentException($"The value for {argumentName} must be 0 or greater.");
    }

    if (!allowZero && parsedValue <= 0)
    {
        throw new ArgumentException($"The value for {argumentName} must be greater than 0.");
    }

    return parsedValue;
}

static void PrintUsage()
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  dotnet run --project dotnet/tls/TlsE2eBenchmark.csproj [-- --scenario classical|pq|all] [--iterations N] [--warmup N] [--payload-bytes N]");
    Console.WriteLine();
    Console.WriteLine("Examples:");
    Console.WriteLine("  dotnet run --project dotnet/tls/TlsE2eBenchmark.csproj");
    Console.WriteLine("  dotnet run --project dotnet/tls/TlsE2eBenchmark.csproj -- --scenario pq --iterations 200 --warmup 10");
}

sealed record AppOptions(
    string? Role,
    string Scenario,
    int Iterations,
    int WarmupIterations,
    int PayloadBytes,
    int Port,
    string? CertificatePath,
    string? CertificatePassword,
    string? TrustedCertificatePath,
    bool ShowHelp);

sealed record ScenarioDefinition(
    string Name,
    string Description,
    string ConfiguredKeyExchangeGroup,
    string OpenSslGroups);

sealed record NegotiationSnapshot(
    string SslProtocol,
    string CipherSuite,
    string PresentedCertificateAlgorithm);

sealed record ClientBenchmarkResult(
    string Scenario,
    string Description,
    string ConfiguredKeyExchangeGroup,
    int Iterations,
    int WarmupIterations,
    int PayloadBytes,
    double ElapsedMilliseconds,
    double AverageMilliseconds,
    double HandshakesPerSecond,
    string SslProtocol,
    string CipherSuite,
    string PresentedCertificateAlgorithm);