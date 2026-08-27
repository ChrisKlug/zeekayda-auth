using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultSigner"/> via its internal client-factory constructor. Happy paths
/// use the SDK's own local-cryptography client (<c>new CryptographyClient(JsonWebKey)</c>), so the
/// algorithm mapping is proven by verifying the produced signature with the exact scheme the
/// ZeeKayDa algorithm names — not by inspecting which enum value was forwarded. Fault paths use a
/// throwing fake client.
/// </summary>
public sealed class KeyVaultSignerTests
{
    private static readonly Uri KeyVersionUri = new("https://fake-vault.vault.azure.net/keys/fake-key/v1");
    private static readonly byte[] SigningInput = "signing input"u8.ToArray();

    private static KeyVaultSigner BuildSigner(CryptographyClient client) =>
        new(_ => client);

    [Theory]
    [InlineData(SigningAlgorithm.RS256, "SHA256", false)]
    [InlineData(SigningAlgorithm.RS384, "SHA384", false)]
    [InlineData(SigningAlgorithm.RS512, "SHA512", false)]
    [InlineData(SigningAlgorithm.PS256, "SHA256", true)]
    [InlineData(SigningAlgorithm.PS384, "SHA384", true)]
    [InlineData(SigningAlgorithm.PS512, "SHA512", true)]
    public async Task SignAsync_signs_with_the_exact_rsa_scheme_the_algorithm_names(
        SigningAlgorithm algorithm, string hashName, bool usePss)
    {
        using var rsa = RSA.Create(2048);
        var signer = BuildSigner(new CryptographyClient(new JsonWebKey(rsa, includePrivateParameters: true)));

        var signature = await signer.SignAsync(
            KeyVersionUri, "v1", algorithm, SigningInput, TestContext.Current.CancellationToken);

        rsa.VerifyData(
                SigningInput, signature.ToArray(), new HashAlgorithmName(hashName),
                usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1)
            .Should().BeTrue($"the signature must verify under the scheme {algorithm} promises relying parties");
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256, "SHA256", "nistP256")]
    [InlineData(SigningAlgorithm.ES384, "SHA384", "nistP384")]
    [InlineData(SigningAlgorithm.ES512, "SHA512", "nistP521")]
    public async Task SignAsync_signs_with_the_exact_ec_scheme_the_algorithm_names(
        SigningAlgorithm algorithm, string hashName, string curveName)
    {
        using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName(curveName));
        var signer = BuildSigner(new CryptographyClient(new JsonWebKey(ecdsa, includePrivateParameters: true)));

        var signature = await signer.SignAsync(
            KeyVersionUri, "v1", algorithm, SigningInput, TestContext.Current.CancellationToken);

        ecdsa.VerifyData(SigningInput, signature.ToArray(), new HashAlgorithmName(hashName))
            .Should().BeTrue($"the signature must verify under the scheme {algorithm} promises relying parties");
    }

    [Fact]
    public async Task SignAsync_rejects_an_algorithm_with_no_key_vault_mapping()
    {
        using var rsa = RSA.Create(2048);
        var signer = BuildSigner(new CryptographyClient(new JsonWebKey(rsa, includePrivateParameters: true)));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", (SigningAlgorithm)999, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<NotSupportedException>();
    }

    [Fact]
    public async Task SignAsync_creates_one_cryptography_client_per_key_version_uri()
    {
        using var rsa = RSA.Create(2048);
        var factoryCalls = new List<Uri>();
        var signer = new KeyVaultSigner(uri =>
        {
            factoryCalls.Add(uri);
            return new CryptographyClient(new JsonWebKey(rsa, includePrivateParameters: true));
        });
        var otherVersionUri = new Uri("https://fake-vault.vault.azure.net/keys/fake-key/v2");

        await signer.SignAsync(KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput, TestContext.Current.CancellationToken);
        await signer.SignAsync(KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput, TestContext.Current.CancellationToken);
        await signer.SignAsync(otherVersionUri, "v2", SigningAlgorithm.RS256, SigningInput, TestContext.Current.CancellationToken);

        factoryCalls.Should().Equal([KeyVersionUri, otherVersionUri],
            "a versioned key URI's material never changes, so its client is built once and cached");
    }

    [Fact]
    public async Task SignAsync_names_the_retry_after_value_when_key_vault_throttles_with_the_header()
    {
        var throttled = new RequestFailedException(new FakeAzureResponse(
            429, new Dictionary<string, string> { ["Retry-After"] = "30" }));
        var signer = BuildSigner(new ThrowingCryptographyClient(throttled));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .Which.Message.Should().Contain("'v1'").And.Contain("(HTTP 429)").And.Contain("Retry after 30",
                "the operator's next action is in the Retry-After header — the message must surface it");
    }

    [Fact]
    public async Task SignAsync_tells_the_operator_to_back_off_when_throttled_without_a_retry_after_header()
    {
        var throttled = new RequestFailedException(new FakeAzureResponse(429));
        var signer = BuildSigner(new ThrowingCryptographyClient(throttled));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .Which.Message.Should().Contain("No Retry-After header");
    }

    [Fact]
    public async Task SignAsync_maps_other_request_failures_with_status_and_error_code()
    {
        var failure = new RequestFailedException(500, "boom", "InternalServerError", innerException: null);
        var signer = BuildSigner(new ThrowingCryptographyClient(failure));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .Which.Message.Should().Contain("'v1'").And.Contain("HTTP 500").And.Contain("ErrorCode: InternalServerError");
    }

    [Fact]
    public async Task SignAsync_lets_cancellation_escape_unwrapped()
    {
        // A cancelled sign is the host shutting down, not a vault failure — wrapping it in
        // AzureKeyVaultSigningException would send the operator to audit a healthy vault.
        var signer = BuildSigner(new ThrowingCryptographyClient(new OperationCanceledException()));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task SignAsync_tells_the_operator_to_back_off_when_throttled_with_no_raw_response_at_all()
    {
        // Distinct from the no-header case: here the SDK exception carries no raw response object
        // whatsoever, so the Retry-After lookup must fail soft rather than dereference it.
        var throttled = new RequestFailedException(429, "throttled");
        var signer = BuildSigner(new ThrowingCryptographyClient(throttled));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .Which.Message.Should().Contain("No Retry-After header");
    }

    [Fact]
    public async Task SignAsync_omits_the_error_code_clause_when_the_sdk_reports_none()
    {
        var failure = new RequestFailedException(500, "boom");
        var signer = BuildSigner(new ThrowingCryptographyClient(failure));

        var act = () => signer.SignAsync(
            KeyVersionUri, "v1", SigningAlgorithm.RS256, SigningInput,
            TestContext.Current.CancellationToken).AsTask();

        (await act.Should().ThrowAsync<AzureKeyVaultSigningException>())
            .Which.Message.Should().NotContain("ErrorCode",
                "an absent SDK error code must not leave a dangling 'ErrorCode:' clause in the operator message");
    }
}
