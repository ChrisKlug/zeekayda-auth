using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultKeyReader"/>: <c>MapVersion</c> as a pure function over SDK data
/// (via the SDK's <see cref="KeyModelFactory"/>), and the network-facing paths — version
/// enumeration, key-material retrieval, and the SDK fault mapping that turns transport failures
/// into stable failure codes with operator remedies — via a <see cref="FakeKeyClient"/> injected
/// through the reader's internal test constructor. Only the real HTTP pipeline itself remains
/// covered by nothing but the known-gap note in
/// <c>Integration/AzureKeyVaultRemoteSigningIntegrationTests.cs</c>.
/// </summary>
public sealed class KeyVaultKeyReaderTests
{
    private static readonly Uri VaultUri = new("https://fake-vault.vault.azure.net/");
    private static readonly Uri VersionUri = new("https://fake-vault.vault.azure.net/keys/fake-key/v1");
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static KeyProperties BuildProperties(DateTimeOffset? createdOn, bool? enabled)
    {
        var properties = KeyModelFactory.KeyProperties(
            id: VersionUri, vaultUri: VaultUri, name: "fake-key", version: "v1",
            managed: false, createdOn: createdOn, updatedOn: null, recoveryLevel: null);
        properties.Enabled = enabled;
        return properties;
    }

    [Fact]
    public void MapVersion_maps_a_complete_listing_entry()
    {
        var properties = BuildProperties(createdOn: T0, enabled: true);
        properties.NotBefore = T0 - TimeSpan.FromDays(1);
        properties.ExpiresOn = T0 + TimeSpan.FromDays(365);

        var info = KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        info.Id.Should().Be(VersionUri);
        info.Version.Should().Be("v1");
        info.Enabled.Should().BeTrue();
        info.CreatedOn.Should().Be(T0);
        info.NotBefore.Should().Be(T0 - TimeSpan.FromDays(1));
        info.ExpiresOn.Should().Be(T0 + TimeSpan.FromDays(365));
    }

    [Fact]
    public void MapVersion_fails_closed_when_CreatedOn_is_absent()
    {
        // An absent CreatedOn treated as ancient would satisfy the pre-activation age gate
        // immediately AND claim the first-ever exemption — the exact failure the gate exists to
        // prevent, reached through the one input the gate cannot see.
        var properties = BuildProperties(createdOn: null, enabled: true);

        var act = () => KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }

    [Fact]
    public void MapVersion_fails_closed_when_Enabled_is_absent()
    {
        // An absent Enabled treated as enabled would bypass the operator's revocation lever.
        var properties = BuildProperties(createdOn: T0, enabled: null);

        var act = () => KeyVaultKeyReader.MapVersion(properties, "fake-key", VaultUri);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*incomplete_version_metadata*");
    }

    // ── Network-facing paths, via the internal test constructor ────────────────────────────────

    private static KeyVaultKeyReader BuildReader(FakeKeyClient client) =>
        new(client, "fake-key", VaultUri);

    private static async Task<List<KeyVaultKeyVersionInfo>> Collect(KeyVaultKeyReader reader)
    {
        var versions = new List<KeyVaultKeyVersionInfo>();
        await foreach (var version in reader.GetKeyVersionsAsync(TestContext.Current.CancellationToken))
            versions.Add(version);
        return versions;
    }

    [Fact]
    public async Task GetKeyVersionsAsync_yields_every_listed_version_mapped()
    {
        var client = new FakeKeyClient
        {
            OnGetVersions = () => FakeAsyncPageable<KeyProperties>.Of(
                BuildProperties(createdOn: T0, enabled: true),
                BuildProperties(createdOn: T0 + TimeSpan.FromDays(1), enabled: false)),
        };

        var versions = await Collect(BuildReader(client));

        versions.Should().HaveCount(2);
        versions[0].CreatedOn.Should().Be(T0);
        versions[0].Enabled.Should().BeTrue();
        versions[1].CreatedOn.Should().Be(T0 + TimeSpan.FromDays(1));
        versions[1].Enabled.Should().BeFalse();
        client.RequestedNames.Should().Equal(["fake-key"],
            "the listing must be for the configured key, nothing else");
    }

    [Theory]
    [InlineData(404, "key_not_found")]
    [InlineData(401, "access_denied")]
    [InlineData(403, "access_denied")]
    [InlineData(500, "startup_failure")]
    public async Task GetKeyVersionsAsync_maps_a_failed_listing_to_a_stable_failure_code(
        int status, string expectedCode)
    {
        var client = new FakeKeyClient
        {
            OnGetVersions = () => FakeAsyncPageable<KeyProperties>.Throwing(
                new RequestFailedException(status, "boom")),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage($"*{expectedCode}*");
    }

    [Fact]
    public async Task GetKeyVersionsAsync_maps_an_unexpected_listing_exception_to_startup_failure()
    {
        var client = new FakeKeyClient
        {
            OnGetVersions = () => FakeAsyncPageable<KeyProperties>.Throwing(
                new InvalidOperationException("SDK internal fault")),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    [Fact]
    public async Task GetKeyVersionsAsync_lets_cancellation_escape_unmapped()
    {
        // A cancelled read is the host shutting down, not a vault misconfiguration — mapping it
        // to a configuration failure would tell the operator to go fix a vault that is fine.
        var client = new FakeKeyClient
        {
            OnGetVersions = () => FakeAsyncPageable<KeyProperties>.Throwing(
                new OperationCanceledException()),
        };

        var act = () => Collect(BuildReader(client));

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private static KeyVaultKey BuildKey(JsonWebKey jsonWebKey) =>
        KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(
                id: VersionUri, vaultUri: VaultUri, name: "fake-key", version: "v1",
                managed: false, createdOn: T0, updatedOn: null, recoveryLevel: null),
            jsonWebKey);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetKeyMaterialAsync_maps_an_rsa_key_to_a_public_only_rsa(bool hsm)
    {
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);
        if (hsm)
            jsonWebKey.KeyType = KeyType.RsaHsm;
        var client = new FakeKeyClient { OnGetKey = _ => BuildKey(jsonWebKey) };

        var (publicKey, keyType) = await BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken);

        using var _ = publicKey;
        keyType.Should().Be(SigningKeyType.Rsa);
        publicKey.Should().BeAssignableTo<RSA>();
        ((RSA)publicKey).ExportParameters(includePrivateParameters: false).Modulus
            .Should().BeEquivalentTo(rsa.ExportParameters(false).Modulus);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GetKeyMaterialAsync_maps_an_ec_key_to_a_public_only_ecdsa(bool hsm)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);
        if (hsm)
            jsonWebKey.KeyType = KeyType.EcHsm;
        var client = new FakeKeyClient { OnGetKey = _ => BuildKey(jsonWebKey) };

        var (publicKey, keyType) = await BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken);

        using var _ = publicKey;
        keyType.Should().Be(SigningKeyType.Ec);
        publicKey.Should().BeAssignableTo<ECDsa>();
    }

    [Fact]
    public async Task GetKeyMaterialAsync_never_exports_rsa_private_parameters_even_when_the_jwk_carries_them()
    {
        // Key Vault's keys/get never returns private halves, but this reader must not be the
        // component that would forward one if it ever did: the mapped key is public-only by
        // construction, so a private export from it must fail.
        using var rsa = RSA.Create(2048);
        var client = new FakeKeyClient
        {
            OnGetKey = _ => BuildKey(new JsonWebKey(rsa, includePrivateParameters: true)),
        };

        var (publicKey, _) = await BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken);

        using var key = publicKey;
        var act = () => ((RSA)key).ExportParameters(includePrivateParameters: true);
        act.Should().Throw<CryptographicException>(
            "the reader maps only the public half, even from a JWK that carries private material");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_never_exports_ec_private_parameters_even_when_the_jwk_carries_them()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var client = new FakeKeyClient
        {
            OnGetKey = _ => BuildKey(new JsonWebKey(ecdsa, includePrivateParameters: true)),
        };

        var (publicKey, _) = await BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken);

        using var key = publicKey;
        var act = () => ((ECDsa)key).ExportParameters(includePrivateParameters: true);
        act.Should().Throw<CryptographicException>(
            "the reader maps only the public half, even from a JWK that carries private material");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_rejects_an_unsupported_key_type()
    {
        using var aes = Aes.Create();
        var client = new FakeKeyClient { OnGetKey = _ => BuildKey(new JsonWebKey(aes)) };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*unsupported_key_type*");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_requests_the_version_it_was_asked_for()
    {
        using var rsa = RSA.Create(2048);
        string? requestedVersion = null;
        var client = new FakeKeyClient
        {
            OnGetKey = version =>
            {
                requestedVersion = version;
                return BuildKey(new JsonWebKey(rsa, includePrivateParameters: false));
            },
        };

        await BuildReader(client).GetKeyMaterialAsync("v7", TestContext.Current.CancellationToken);

        requestedVersion.Should().Be("v7");
        client.RequestedNames.Should().Equal(["fake-key"],
            "the material must be fetched for the configured key, nothing else");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_includes_the_sdk_error_code_in_the_failure_when_present()
    {
        var client = new FakeKeyClient
        {
            OnGetKey = _ => throw new RequestFailedException(
                404, "not found", "KeyNotFound", innerException: null),
        };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*key_not_found*ErrorCode: KeyNotFound*");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_omits_the_error_code_clause_when_the_sdk_reports_none()
    {
        var client = new FakeKeyClient
        {
            OnGetKey = _ => throw new RequestFailedException(404, "not found"),
        };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.Message.Should().NotContain("ErrorCode",
                "an absent SDK error code must not leave a dangling 'ErrorCode:' clause in the operator message");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_maps_an_unexpected_exception_to_startup_failure()
    {
        var client = new FakeKeyClient
        {
            OnGetKey = _ => throw new InvalidOperationException("SDK internal fault"),
        };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    // ZeeKayDaConfigurationFailure.Message is a plain string on public API surface that
    // SecretSanitizingLogger cannot redact, so no caught exception's own Message may reach it.
    // RequestFailedException.Message carries the response content and headers; a cryptographic
    // exception can echo the input it failed to parse. The type is named instead, and the original
    // travels as InnerException. See docs/decisions and .claude/agents/developer.md.

    [Fact]
    public async Task GetKeyMaterialAsync_does_not_leak_the_sdk_exception_message_into_the_failure()
    {
        var thrown = new RequestFailedException(500, "vault-secret-in-response-body");
        var client = new FakeKeyClient { OnGetKey = _ => throw thrown };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        var thrownAssertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrownAssertion.Which.Message.Should().NotContain("vault-secret-in-response-body",
            "RequestFailedException.Message carries the response content and headers");
        thrownAssertion.Which.Message.Should().Contain("Azure.RequestFailedException",
            "the operator still needs the exception type to diagnose the failure");
        thrownAssertion.Which.InnerException.Should().BeSameAs(thrown,
            "the root cause stays available to operators as InnerException");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_does_not_leak_an_unexpected_exception_message_into_the_failure()
    {
        var thrown = new InvalidOperationException("connection-string-in-message");
        var client = new FakeKeyClient { OnGetKey = _ => throw thrown };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        var thrownAssertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrownAssertion.Which.Message.Should().NotContain("connection-string-in-message",
            "an arbitrary provider exception message may carry credential material");
        thrownAssertion.Which.Message.Should().Contain("System.InvalidOperationException");
        thrownAssertion.Which.InnerException.Should().BeSameAs(thrown);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_does_not_leak_an_unexpected_exception_message_into_the_failure()
    {
        var thrown = new InvalidOperationException("connection-string-in-message");
        var client = new FakeKeyClient
        {
            OnGetVersions = () => FakeAsyncPageable<KeyProperties>.Throwing(thrown),
        };

        var act = () => Collect(BuildReader(client));

        var thrownAssertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrownAssertion.Which.Message.Should().NotContain("connection-string-in-message");
        thrownAssertion.Which.Message.Should().Contain("System.InvalidOperationException");
        thrownAssertion.Which.InnerException.Should().BeSameAs(thrown);
    }

    [Fact]
    public async Task GetKeyMaterialAsync_maps_a_malformed_jwk_to_startup_failure()
    {
        // The JWK conversion stays inside the fault-mapping try for this reason: a vault that
        // returns an RSA-typed key with unusable parameters makes ToRSA throw, and that must reach
        // the operator as a stable failure code, not as a raw CryptographicException from the SDK.
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);
        jsonWebKey.N = [];
        jsonWebKey.E = [];
        var client = new FakeKeyClient { OnGetKey = _ => BuildKey(jsonWebKey) };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*startup_failure*");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_does_not_reclassify_an_unsupported_key_type_as_startup_failure()
    {
        // A catch(ZeeKayDaConfigurationException) re-throw arm sits ahead of the broad SDK-fault
        // catch for this reason: without it that catch flattens this well-formed failure into a
        // generic startup_failure, and the operator is told to go investigate a vault that is
        // working correctly. Before the ex.Message leak was removed this was hidden — the
        // unsupported_key_type code reached the operator only by riding along inside the
        // interpolated inner message, so the older test passed for the wrong reason.
        using var aes = Aes.Create();
        var client = new FakeKeyClient { OnGetKey = _ => BuildKey(new JsonWebKey(aes)) };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        var thrownAssertion = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrownAssertion.Which.Message.Should().Contain("unsupported_key_type");
        thrownAssertion.Which.Message.Should().NotContain("startup_failure",
            "a well-formed failure must not be re-classified by the SDK fault handler");
    }

    [Fact]
    public async Task GetKeyMaterialAsync_lets_cancellation_escape_unmapped()
    {
        var client = new FakeKeyClient
        {
            OnGetKey = _ => throw new OperationCanceledException(),
        };

        var act = () => BuildReader(client)
            .GetKeyMaterialAsync("v1", TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
