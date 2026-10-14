using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Observes the Windows user key store while a <see cref="PfxFileSigningKeySource"/> signer is live.
/// An OS-backed certificate carrying a private key is the only thing that writes a key container
/// there, so an unchanged key store is the observable proof that none was built.
/// </summary>
/// <remarks>
/// Runs alone: any other test loading a PFX with <see cref="X509CertificateLoader"/> at the same
/// time would write its own key container into the snapshot.
/// </remarks>
[Collection(nameof(PfxFileSigningKeyStoreTests))]
[CollectionDefinition(nameof(PfxFileSigningKeyStoreTests), DisableParallelization = true)]
public sealed class PfxFileSigningKeyStoreTests
{
    private const string Password = "correct horse battery staple";

    [Fact]
    public async Task CreateSignerAsync_never_constructs_a_certificate_carrying_a_private_key()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "the user key store on disk is a Windows behaviour.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var now = DateTimeOffset.UtcNow;
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", now.AddDays(-1), now.AddDays(365));
        var path = tempDir.WritePfxFile("current.pfx", certificate, Password);
        var options = new PfxFileSigningOptions { Algorithm = SigningAlgorithm.RS256 };
        options.Files.Add(new PfxFile(path, _ => Task.FromResult(Password)));
        var sut = new PfxFileSigningKeySource(
            Options.Create(options),
            new FileSigningKeyReader(TestSanitizingLogger.Create(NullLogger<FileSigningKeyReader>.Instance)));
        var keySet = (await sut.ReadAsync(ct)).Keys;
        var before = UserKeyStoreFiles();

        using var signer = await sut.CreateSignerAsync(keySet.Single().Id, ct);
        var signingInput = "header.payload"u8.ToArray();
        var signature = await signer.SignAsync(signingInput, ct);

        UserKeyStoreFiles().Except(before).Should().BeEmpty("the key is imported in memory, not into the key store");
        using var rsa = RSA.Create(keySet.Single().PublicKey.RsaPublicParameters!.Value);
        rsa.VerifyData(signingInput, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue("the signer must sign with the listed certificate's key pair");
    }

    // CNG writes user keys under Crypto\Keys, CAPI under Crypto\RSA\<SID>; both sit below Crypto.
    private static HashSet<string> UserKeyStoreFiles()
    {
        var store = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Crypto");

        return Directory.Exists(store)
            ? [.. Directory.EnumerateFiles(store, "*", SearchOption.AllDirectories)]
            : [];
    }
}
