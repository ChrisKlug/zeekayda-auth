using System.Xml.Linq;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
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
    public void AddAzureKeyVaultRemoteSigning_throws_ArgumentNullException_when_credential_is_null()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("credential");
    }

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        // An extension method is callable on a null receiver, so the guard is the only thing between
        // a null builder and a NullReferenceException from builder.Services one line later.
        ZeeKayDaAuthBuilder builder = null!;

        var act = () => builder.AddAzureKeyVaultRemoteSigning(
            KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthBuilder builder = null!;

        var act = () => builder.AddAzureKeyVaultCachedSigning(
            CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<ArgumentNullException>().WithParameterName("builder");
    }

    // ── A host's own TimeProvider survives registration ──────────────────────────────────────────
    //
    // Deliberately NOT a test that "the extension registers a TimeProvider". It does contain such a
    // line, but AddZeeKayDaSigningKeySource — called earlier in the same method — has already
    // TryAdd-registered one, so deleting the extension's own line changes nothing observable. A test
    // asserting TimeProvider resolves would pass either way and imply coverage it does not have.
    // Those two statements are equivalent mutants; they are justified in the PR, not faked closed.
    //
    // What is worth pinning is the TryAdd semantics a host actually depends on.

    [Fact]
    public void AddAzureKeyVaultRemoteSigning_keeps_a_TimeProvider_the_host_already_registered()
    {
        // TryAddSingleton, not AddSingleton: a host driving a simulated clock must not have it
        // silently replaced by the system clock.
        var services = new ServiceCollection();
        var hostProvider = new FakeTimeProvider();
        services.AddSingleton<TimeProvider>(hostProvider);
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<TimeProvider>().Should().BeSameAs(hostProvider);
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_keeps_a_TimeProvider_the_host_already_registered()
    {
        var services = new ServiceCollection();
        var hostProvider = new FakeTimeProvider();
        services.AddSingleton<TimeProvider>(hostProvider);
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<TimeProvider>().Should().BeSameAs(hostProvider);
    }

    // ── Double-registration guard ─────────────────────────────────────────────────────────────────


    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_when_a_signing_key_source_is_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        var act = () => builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>();
    }

    // ── Successful registration ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_registers_the_signing_key_ring_over_the_key_vault_source()
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
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
        provider.GetService<ISigningKeySource>().Should().BeNull(
            "the ring constructs and owns the one source instance — nothing may reach it through the container");
    }

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_configures_the_options_it_was_called_with()
    {
        var services = new ServiceCollection();
        var credential = new FakeTokenCredential();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.ES256, credential);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AzureKeyVaultRemoteSigningOptions>>().Value;
        options.KeyIdentifier.Should().Be(KeyIdentifier);
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
        options.Credential.Should().BeSameAs(credential);
        options.PreviousVersionsToPublish.Should().Be(1, "one previous version publishing is the documented default");
        options.PreActivationDelay.Should().Be(TimeSpan.FromDays(1), "a one-day pre-activation delay is the documented default");
    }

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_applies_the_configure_callback()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential(),
            options => options.PreActivationDelay = TimeSpan.FromHours(2));

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AzureKeyVaultRemoteSigningOptions>>().Value;
        options.PreActivationDelay.Should().Be(TimeSpan.FromHours(2));
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
    public void AddAzureKeyVaultCachedSigning_throws_ArgumentNullException_when_credential_is_null()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("credential");
    }

    // ── AddAzureKeyVaultCachedSigning: double-registration guard ────────────────────────────────


    [Fact]
    public void AddAzureKeyVaultRemoteSigning_throws_when_AddAzureKeyVaultCachedSigning_already_registered()
    {
        // Only one signing key provider is allowed. Both Key Vault providers now register through
        // AddZeeKayDaSigningKeySource, whose own guard rejects a second source in either order —
        // this closes the gap accepted in #548, where remote-then-cached was undetectable.
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        var act = () => builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*signing key source*", "the key-source guard, not the transitional IJwtSigningService guard, must be the one that fires");
    }

    [Fact]
    public void AddAzureKeyVaultCachedSigning_throws_when_AddAzureKeyVaultRemoteSigning_already_registered()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*signing key source*", "the key-source guard, not the transitional IJwtSigningService guard, must be the one that fires");
    }

    /// <summary>
    /// Issue #511: a second call with *different* options must fail loudly rather than silently
    /// composing two configurations onto one registration.
    /// </summary>
    [Fact]
    public void AddAzureKeyVaultCachedSigning_after_AddAzureKeyVaultCachedSigning_with_different_options_throws()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);
        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        var act = () => builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.ES256, new FakeTokenCredential());

        act.Should().Throw<InvalidOperationException>();
    }

    // ── AddAzureKeyVaultCachedSigning: successful registration ──────────────────────────────────

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_registers_the_signing_key_ring_over_the_key_vault_source()
    {
        var services = new ServiceCollection();
        // The certificate seam must be registered before the extension runs — it only
        // TryAddSingleton-registers the real implementation, so a pre-registered fake wins.
        services.AddSingleton<IKeyVaultCertificateReader>(new FakeKeyVaultCertificateReader());
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
        provider.GetService<ISigningKeySource>().Should().BeNull(
            "the ring constructs and owns the one source instance — nothing may reach it through the container");
    }

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_configures_the_options_it_was_called_with()
    {
        var services = new ServiceCollection();
        var credential = new FakeTokenCredential();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.ES256, credential);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AzureKeyVaultCachedSigningOptions>>().Value;
        options.CertificateIdentifier.Should().Be(CertificateIdentifier);
        options.Algorithm.Should().Be(SigningAlgorithm.ES256);
        options.Credential.Should().BeSameAs(credential);
        options.PreviousVersionsToPublish.Should().Be(1, "one previous version publishing is the documented default");
        options.PreActivationDelay.Should().Be(TimeSpan.FromDays(1), "a one-day pre-activation delay is the documented default");
    }

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_applies_the_configure_callback()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential(),
            options => options.PreviousVersionsToPublish = 3);

        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AzureKeyVaultCachedSigningOptions>>().Value;
        options.PreviousVersionsToPublish.Should().Be(3);
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

    // ── Control presence: the startup validator and the real Key Vault seams ─────────────────────
    //
    // These are control-presence tests, not DI-resolution assertions: a missing validator
    // registration lets a misconfigured provider fail open past ValidateOnStart, and a missing
    // seam registration means the provider cannot reach the vault at all.

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_registers_the_startup_options_validator()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        provider.GetServices<IValidateOptions<AzureKeyVaultRemoteSigningOptions>>()
            .Should().ContainSingle(v => v is AzureKeyVaultRemoteSigningOptionsValidator);
    }

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_registers_the_startup_options_validator()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        provider.GetServices<IValidateOptions<AzureKeyVaultCachedSigningOptions>>()
            .Should().ContainSingle(v => v is AzureKeyVaultCachedSigningOptionsValidator);
    }

    [Fact]
    public async Task AddAzureKeyVaultRemoteSigning_registers_the_real_key_vault_seams_by_default()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultRemoteSigning(KeyIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IKeyVaultKeyReader>().Should().BeOfType<KeyVaultKeyReader>();
        provider.GetRequiredService<IKeyVaultSigner>().Should().BeOfType<KeyVaultSigner>();
        provider.GetRequiredService<TimeProvider>().Should().BeSameAs(TimeProvider.System);
    }

    [Fact]
    public async Task AddAzureKeyVaultCachedSigning_registers_the_real_key_vault_seams_by_default()
    {
        var services = new ServiceCollection();
        var builder = new ZeeKayDaAuthBuilder(services);

        builder.AddAzureKeyVaultCachedSigning(CertificateIdentifier, SigningAlgorithm.RS256, new FakeTokenCredential());

        await using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IKeyVaultCertificateReader>().Should().BeOfType<KeyVaultCertificateReader>();
        provider.GetRequiredService<TimeProvider>().Should().BeSameAs(TimeProvider.System);
    }
}
