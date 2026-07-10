using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.MacOS.Interop;

namespace ZeeKayDa.Auth.MacOS.Tests.Integration;

/// <summary>
/// Test-only helpers that install and remove real items in the current user's login Keychain, for
/// the macOS-only integration tests in this folder. Mirrors
/// <c>ZeeKayDa.Auth.Windows.Tests.Integration.CertificateStoreReaderTests.InstalledTestCertificate</c>'s
/// role for the Windows Certificate Store provider.
/// </summary>
[SupportedOSPlatform("macos")]
internal static class InstalledTestKeychainItems
{
    /// <summary>
    /// Generates a bare RSA key pair directly in the login Keychain via <c>SecKeyCreateRandomKey</c>
    /// (the same native call the production <see cref="KeychainItemReader"/> reads back), under a
    /// fresh, unique label.
    /// </summary>
    public static InstalledBareKey CreateBareRsaKey(int keySizeBits = 2048) => InstalledBareKey.CreateRsa(keySizeBits);

    /// <summary>Generates a bare EC (P-256) key pair directly in the login Keychain.</summary>
    public static InstalledBareKey CreateBareEcKey() => InstalledBareKey.CreateEc();

    /// <summary>
    /// Installs a self-signed certificate and its private key as a matched identity in the login
    /// Keychain, via the same <c>security import</c> CLI path documented for operators
    /// (issue #290's docs requirement).
    /// </summary>
    public static InstalledIdentity CreateIdentity(string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        InstalledIdentity.Create(subjectName, notBefore, notAfter);

    /// <summary>Installs a certificate with no matching private key (for the private-key-not-found negative path).</summary>
    public static InstalledCertificateOnly CreateCertificateOnly(string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        InstalledCertificateOnly.Create(subjectName, notBefore, notAfter);

    /// <summary>
    /// Generates an RSA key pair whose label is set only on the <em>public</em> half (via
    /// <c>kSecPublicKeyAttrs</c>), leaving the private half unlabeled — so a lookup for this label
    /// finds a real Keychain item, but not a usable private key (AC #9's "exists but lacks signing
    /// capability" case, reached via the same code path a mislabeled public key or a symmetric key
    /// would take).
    /// </summary>
    public static InstalledBareKey CreatePublicKeyOnlyLabel() => InstalledBareKey.CreateRsaWithPublicOnlyLabel();

    internal sealed class InstalledBareKey : IDisposable
    {
        public required string Label { get; init; }

        public static InstalledBareKey CreateRsa(int keySizeBits)
        {
            var label = UniqueLabel("rsa-key");
            using var keySizeValue = new SafeCFTypeRefHandle(CoreFoundationInterop.CreateNumber(keySizeBits));
            using var query = new CFDictionaryBuilder()
                .Add(SecurityInterop.KSecAttrKeyType, SecurityInterop.KSecAttrKeyTypeRsa)
                .Add(SecurityInterop.KSecAttrKeySizeInBits, keySizeValue.DangerousGetHandle())
                .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
                .Add(TestKeychainInterop.KSecAttrIsPermanent, CoreFoundationInterop.KCFBooleanTrue)
                .Build();

            using var key = TestKeychainInterop.CreateRandomKey(query.DangerousGetHandle());
            return new InstalledBareKey { Label = label };
        }

        public static InstalledBareKey CreateEc()
        {
            var label = UniqueLabel("ec-key");
            using var keySizeValue = new SafeCFTypeRefHandle(CoreFoundationInterop.CreateNumber(256));
            using var query = new CFDictionaryBuilder()
                .Add(SecurityInterop.KSecAttrKeyType, SecurityInterop.KSecAttrKeyTypeEcSecPrimeRandom)
                .Add(SecurityInterop.KSecAttrKeySizeInBits, keySizeValue.DangerousGetHandle())
                .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
                .Add(TestKeychainInterop.KSecAttrIsPermanent, CoreFoundationInterop.KCFBooleanTrue)
                .Build();

            using var key = TestKeychainInterop.CreateRandomKey(query.DangerousGetHandle());
            return new InstalledBareKey { Label = label };
        }

        public static InstalledBareKey CreateRsaWithPublicOnlyLabel()
        {
            var label = UniqueLabel("public-only-key");
            using var keySizeValue = new SafeCFTypeRefHandle(CoreFoundationInterop.CreateNumber(2048));
            using var labelValue = new SafeCFTypeRefHandle(CoreFoundationInterop.CreateString(label));
            using var publicKeyAttrs = new CFDictionaryBuilder()
                .Add(SecurityInterop.KSecAttrLabel, labelValue.DangerousGetHandle())
                .Build();

            using var query = new CFDictionaryBuilder()
                .Add(SecurityInterop.KSecAttrKeyType, SecurityInterop.KSecAttrKeyTypeRsa)
                .Add(SecurityInterop.KSecAttrKeySizeInBits, keySizeValue.DangerousGetHandle())
                .Add(TestKeychainInterop.KSecAttrIsPermanent, CoreFoundationInterop.KCFBooleanTrue)
                .Add(TestKeychainInterop.KSecPublicKeyAttrs, publicKeyAttrs.DangerousGetHandle())
                .Build();

            using var key = TestKeychainInterop.CreateRandomKey(query.DangerousGetHandle());
            return new InstalledBareKey { Label = label };
        }

        public void Dispose() => TestKeychainInterop.DeleteKeyByLabel(Label);
    }

    internal sealed class InstalledIdentity : IDisposable
    {
        public required string Label { get; init; }
        public required string TemporaryPfxPath { get; init; }

        public static InstalledIdentity Create(string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var label = UniqueLabel(subjectName);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={label}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(notBefore, notAfter);

            const string password = "zeekayda-test-only";
            var pfxBytes = certificate.Export(X509ContentType.Pfx, password);
            var pfxPath = Path.Combine(Path.GetTempPath(), $"{label}.p12");
            File.WriteAllBytes(pfxPath, pfxBytes);

            RunSecurityCli(false, "import", pfxPath, "-k", TargetKeychainPath.Value, "-P", password, "-A");

            return new InstalledIdentity { Label = label, TemporaryPfxPath = pfxPath };
        }

        public void Dispose()
        {
            RunSecurityCli(true, "delete-identity", "-c", Label, TargetKeychainPath.Value);
            File.Delete(TemporaryPfxPath);
        }
    }

    internal sealed class InstalledCertificateOnly : IDisposable
    {
        public required string Label { get; init; }
        public required string TemporaryCerPath { get; init; }

        public static InstalledCertificateOnly Create(string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var label = UniqueLabel(subjectName);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={label}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(notBefore, notAfter);

            var derBytes = certificate.Export(X509ContentType.Cert);
            var cerPath = Path.Combine(Path.GetTempPath(), $"{label}.cer");
            File.WriteAllBytes(cerPath, derBytes);

            RunSecurityCli(false, "add-certificates", "-k", TargetKeychainPath.Value, cerPath);

            return new InstalledCertificateOnly { Label = label, TemporaryCerPath = cerPath };
        }

        public void Dispose()
        {
            RunSecurityCli(true, "delete-certificate", "-c", Label, TargetKeychainPath.Value);
            File.Delete(TemporaryCerPath);
        }
    }

    /// <summary>
    /// Resolves the current default keychain path — not a hardcoded <c>login.keychain-db</c> path
    /// — so these helpers follow whatever keychain the environment has set as default: the real
    /// login keychain for a local developer run, or CI's dedicated, already-authorized keychain
    /// (<c>ci-signing.keychain-db</c>, set up in <c>ci.yml</c>) on a hosted runner.
    /// </summary>
    private static readonly Lazy<string> TargetKeychainPath = new(ResolveDefaultKeychainPath);

    private static string ResolveDefaultKeychainPath()
    {
        var startInfo = new ProcessStartInfo("security")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("default-keychain");
        startInfo.ArgumentList.Add("-d");
        startInfo.ArgumentList.Add("user");

        using var process = Process.Start(startInfo)!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            var stderr = process.StandardError.ReadToEnd();
            throw new InvalidOperationException(
                $"`security default-keychain -d user` failed with exit code {process.ExitCode}: {stderr}");
        }

        // Output is the keychain path, quoted and newline-terminated, e.g.
        // `    "/Users/x/Library/Keychains/login.keychain-db"\n`.
        return output.Trim().Trim('"');
    }

    private static string UniqueLabel(string prefix) => $"zeekayda-macos-test-{prefix}-{Guid.NewGuid():N}";

    private static void RunSecurityCli(bool ignoreFailure, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("security")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo)!;
        process.WaitForExit();

        if (!ignoreFailure && process.ExitCode != 0)
        {
            var stderr = process.StandardError.ReadToEnd();
            throw new InvalidOperationException(
                $"`security {string.Join(' ', arguments)}` failed with exit code {process.ExitCode}: {stderr}");
        }
    }
}
