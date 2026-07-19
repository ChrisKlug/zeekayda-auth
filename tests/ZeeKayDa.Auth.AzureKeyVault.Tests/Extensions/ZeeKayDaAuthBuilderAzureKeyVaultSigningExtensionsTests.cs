using System.Xml.Linq;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Extensions;

public sealed class ZeeKayDaAuthBuilderAzureKeyVaultSigningExtensionsTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");
    private static readonly KeyVaultKeyIdentifier KeyIdentifier = new(KeyIdentifierUri);
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");
    private static readonly KeyVaultCertificateIdentifier CertificateIdentifier = new(CertificateIdentifierUri);

    // ── Argument validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_ArgumentNullException_when_credential_is_null()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("credential");
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_resolves_IJwtSigningService_as_the_azure_key_vault_implementation()
    {
        var services = new ServiceCollection();
        // The two Key Vault seams must be registered before the extension runs — it only
        // TryAddSingleton-registers the real implementations, so a pre-registered fake wins.
        services.AddSingleton<IKeyVaultKeyReader>(new FakeKeyVaultKeyReader());
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        // SecretSanitizingLogger<T> (registered by AddZeeKayDaAuthCore) needs a real ILogger<T> to
        // resolve; a plain ServiceCollection has no logging provider registered by default.
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<AzureKeyVaultRemoteSigningJwtSigningService>();
    }

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IKeyVaultKeyReader>(new FakeKeyVaultKeyReader());
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        returned.Should().BeSameAs(builder);
    }

    // ── XML doc <remarks> verbatim text (issue AC #8) ────────────────────────────────────────────

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_remarks_first_paragraph_states_exact_AC8_sentence()
    {
        var xmlPath = Path.Join(AppContext.BaseDirectory, "ZeeKayDa.Auth.AzureKeyVault.xml");
        File.Exists(xmlPath).Should().BeTrue(
            $"the referenced project's generated XML doc file should be copied to '{xmlPath}' " +
            "(GenerateDocumentationFile is enabled repo-wide via Directory.Build.props)");

        var doc = XDocument.Load(xmlPath);
        var member = doc.Descendants("member")
            .FirstOrDefault(m => (string?)m.Attribute("name") is { } name &&
                name.StartsWith(
                    "M:Microsoft.Extensions.DependencyInjection.ZeeKayDaAuthBuilderAzureKeyVaultSigningExtensions.AddAzureKeyVaultRemoteSigning",
                    StringComparison.Ordinal));

        member.Should().NotBeNull("the generated XML doc should contain an entry for AddAzureKeyVaultRemoteSigning");

        var firstPara = member!.Element("remarks")!.Element("para");
        firstPara.Should().NotBeNull("the <remarks> section should begin with a <para>");

        // XElement.Value flattens child markup (e.g. the <c>AddAzureKeyVaultCachedSigning</c> tag)
        // down to its plain text content, so the code-formatted name appears here without any
        // surrounding tag syntax. Embedded newlines/indentation from the source doc comment are
        // collapsed to single spaces before comparing, since only the semantic text is normative.
        var normalized = System.Text.RegularExpressions.Regex.Replace(firstPara!.Value, @"\s+", " ").Trim();

        normalized.Should().Be(
            "Signing is performed remotely inside Azure Key Vault. The private key never leaves the " +
            "vault and is never held in process memory. Use AddAzureKeyVaultCachedSigning if Key " +
            "Vault latency or throttling limits are a concern.");
    }

    // ── AddAzureKeyVaultCachedSigning: argument validation ──────────────────────────────────────

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        var act = () => ((ZeeKayDaAuthBuilder)null!).AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_ArgumentNullException_when_credential_is_null()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("credential");
    }

    // ── AddAzureKeyVaultCachedSigning: double-registration guard ────────────────────────────────

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_InvalidOperationException_when_IJwtSigningService_already_registered()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IJwtSigningService>(NoOpJwtSigningService.Instance);
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_InvalidOperationException_when_AddAzureKeyVaultRemoteSigning_already_registered()
    {
        // Only one signing key provider is allowed — the two Key Vault variants share the same
        // IJwtSigningService registration guard, so mixing them in one host must also be rejected.
        var services = new ServiceCollection();
        services.AddSingleton<IKeyVaultKeyReader>(new FakeKeyVaultKeyReader());
        services.AddSingleton<IKeyVaultSigner>(new FakeKeyVaultSigner());
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*IJwtSigningService*already registered*");
    }

    // ── AddAzureKeyVaultCachedSigning: successful registration ──────────────────────────────────

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_resolves_IJwtSigningService_as_the_azure_key_vault_cached_implementation()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IKeyVaultCertificateReader>(new FakeKeyVaultCertificateReader());
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        var service = provider.GetRequiredService<IJwtSigningService>();
        service.Should().BeOfType<AzureKeyVaultCachedSigningJwtSigningService>();
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_returns_builder_for_chaining()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IKeyVaultCertificateReader>(new FakeKeyVaultCertificateReader());
        var builder = new ZeeKayDaAuthBuilder(services);

        var returned = builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        returned.Should().BeSameAs(builder);
    }

    // ── AddAzureKeyVaultCachedSigning: XML doc <remarks> verbatim text (issue AC #8) ─────────────

    [Fact]
    public void AddAzureKeyVaultCachedSigning_remarks_first_paragraph_states_exact_AC8_sentence()
    {
        var xmlPath = Path.Join(AppContext.BaseDirectory, "ZeeKayDa.Auth.AzureKeyVault.xml");
        File.Exists(xmlPath).Should().BeTrue(
            $"the referenced project's generated XML doc file should be copied to '{xmlPath}' " +
            "(GenerateDocumentationFile is enabled repo-wide via Directory.Build.props)");

        var doc = XDocument.Load(xmlPath);
        var member = doc.Descendants("member")
            .FirstOrDefault(m => (string?)m.Attribute("name") is { } name &&
                name.StartsWith(
                    "M:Microsoft.Extensions.DependencyInjection.ZeeKayDaAuthBuilderAzureKeyVaultSigningExtensions.AddAzureKeyVaultCachedSigning",
                    StringComparison.Ordinal));

        member.Should().NotBeNull("the generated XML doc should contain an entry for AddAzureKeyVaultCachedSigning");

        var firstPara = member!.Element("remarks")!.Element("para");
        firstPara.Should().NotBeNull("the <remarks> section should begin with a <para>");

        // XElement.Value flattens child markup down to its plain text content. A self-closing
        // <see cref="..."/> element (unlike a <c>...</c> element with visible inner text)
        // contributes NO text at all to .Value — see the sibling AddAzureKeyVaultRemoteSigning test
        // above, whose equivalent sentence uses <c>AddAzureKeyVaultCachedSigning</c> specifically so
        // its exact wording survives this flattening. Embedded newlines/indentation are collapsed to
        // single spaces before comparing, since only the semantic text is normative.
        var normalized = System.Text.RegularExpressions.Regex.Replace(firstPara!.Value, @"\s+", " ").Trim();

        normalized.Should().Be(
            "The private key is downloaded from Azure Key Vault at startup and cached in process " +
            "memory. Signing is performed locally. An attacker who achieves process memory read gets " +
            "a permanent copy of the signing key. Use AddAzureKeyVaultRemoteSigning if the private " +
            "key must never leave the vault.",
            "AC #8 requires this exact sentence to lead the <remarks> section, verbatim, including the " +
            "method name — if this fails, check whether the source uses <see cref=\"AddAzureKeyVaultRemoteSigning\"/> " +
            "(self-closing, contributes no visible text to the compiled XML doc) instead of " +
            "<c>AddAzureKeyVaultRemoteSigning</c> (which does)");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private sealed class NoOpJwtSigningService : IJwtSigningService
    {
        public static readonly NoOpJwtSigningService Instance = new();

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
