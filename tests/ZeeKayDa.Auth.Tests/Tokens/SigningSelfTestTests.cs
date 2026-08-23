using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningSelfTest.RunAsync"/> directly: the self-test payload's non-JWS shape,
/// and that it is fresh on every invocation rather than a compile-time constant.
/// </summary>
public sealed class SigningSelfTestTests
{
    private sealed class CapturingSigner(RSA rsa) : ISigner
    {
        public ReadOnlyMemory<byte>? LastSigningInput { get; private set; }

        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            LastSigningInput = signingInput;
            return new ValueTask<ReadOnlyMemory<byte>>(
                rsa.SignData(signingInput.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public void Dispose()
        {
        }
    }

    [Fact]
    public async Task RunAsync_signs_a_payload_that_contains_a_space_and_no_dot()
    {
        using var rsa = RSA.Create(2048);
        var signer = new CapturingSigner(rsa);
        var key = BuildKey(rsa);

        await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        var payload = Encoding.ASCII.GetString(signer.LastSigningInput!.Value.Span);
        payload.Should().Contain(" ");
        payload.Should().NotContain(".");
    }

    [Fact]
    public async Task RunAsync_signs_a_different_payload_on_each_invocation()
    {
        using var rsa = RSA.Create(2048);
        var signer = new CapturingSigner(rsa);
        var key = BuildKey(rsa);

        await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);
        var first = signer.LastSigningInput!.Value.ToArray();

        await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);
        var second = signer.LastSigningInput!.Value.ToArray();

        second.Should().NotEqual(first);
    }

    [Fact]
    public async Task RunAsync_throws_self_test_failed_when_the_signature_does_not_verify()
    {
        using var rsa = RSA.Create(2048);
        using var otherRsa = RSA.Create(2048);
        var signer = new CapturingSigner(otherRsa);
        var key = BuildKey(rsa); // published public key does not match the signer's private key

        var act = async () => await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    private static SigningKey BuildKey(RSA rsa) =>
        new(new SourceKeyId("current"), "kid", SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), null);
}
