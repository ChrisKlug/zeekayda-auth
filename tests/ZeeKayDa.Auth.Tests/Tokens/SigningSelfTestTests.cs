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

        public Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            LastSigningInput = signingInput;
            return Task.FromResult<ReadOnlyMemory<byte>>(
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

    [Fact]
    public async Task RunAsync_throws_self_test_failed_when_an_EC_signer_does_not_pair_with_the_key()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new EcSigner(otherEc);
        var key = BuildKey(ec);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task RunAsync_throws_self_test_failed_when_the_signer_returns_bytes_that_are_not_a_signature()
    {
        // A wrong-length blob is not a mismatch a verifier can weigh; on some platforms it throws.
        // Either way it is a failed self-test, never a crash out of the ring.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new GarbageSigner();
        var key = BuildKey(ec);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task RunAsync_keeps_the_verifiers_own_exception_as_the_inner_exception_of_a_failed_self_test()
    {
        // A verifier that cannot weigh the signature at all is a failed self-test, fail-closed, but
        // the operator must see why: a crypto-stack fault must not read as a key that does not pair.
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CapturingSigner(rsa);
        var keyThatCannotBeVerifiedUnderItsAlgorithm = new SigningKey(
            new SourceKeyId("current"), "kid", SigningAlgorithm.RS256, PublicKeyParameters.FromEc(ec.ExportParameters(false)), DateTimeOffset.MinValue, DateTimeOffset.MaxValue);

        var act = async () => await SigningSelfTest.RunAsync(signer, keyThatCannotBeVerifiedUnderItsAlgorithm, TestContext.Current.CancellationToken);

        var exception = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        exception.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
        exception.InnerException.Should().BeOfType<NotSupportedException>("the verifier's own refusal of RS256 over an EC key is the cause the operator needs")
            .Which.Message.Should().Contain("RS256");
    }

    [Fact]
    public async Task RunAsync_throws_self_test_unavailable_naming_only_the_type_when_the_signer_throws()
    {
        // A remote signer's exception can carry a request URL or a credential; the failure names the
        // type and keeps the original as the inner exception for the operator.
        using var rsa = RSA.Create(2048);
        var signer = new ThrowingSigner(new InvalidOperationException("vault call failed: Authorization: Bearer hunter2"));
        var key = BuildKey(rsa);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        var exception = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        var failure = exception.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_unavailable").Subject;
        failure.Message.Should().Contain(typeof(InvalidOperationException).FullName!).And.NotContain("hunter2");
        exception.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    [Fact]
    public async Task RunAsync_lets_the_callers_own_cancellation_propagate()
    {
        using var rsa = RSA.Create(2048);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var signer = new ThrowingSigner(new OperationCanceledException(cancellation.Token));
        var key = BuildKey(rsa);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, cancellation.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task RunAsync_reports_a_signer_cancelled_through_a_linked_token_as_the_callers_cancellation()
    {
        // A signer that links the caller's token to its own (as the Azure SDK does) throws with the
        // linked token. On shutdown that is still the caller's cancellation, not a broken signer.
        using var rsa = RSA.Create(2048);
        using var callers = new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(callers.Token);
        await callers.CancelAsync();
        var signer = new ThrowingSigner(new OperationCanceledException(linked.Token));
        var key = BuildKey(rsa);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, callers.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task RunAsync_treats_a_cancellation_the_signer_raised_itself_as_self_test_unavailable()
    {
        // A remote signer's own timeout surfaces as a cancellation while the caller's token is
        // live; that is the signer failing, and the handoff must fail closed under the named code
        // rather than end as if the caller had cancelled.
        using var rsa = RSA.Create(2048);
        var signer = new ThrowingSigner(new TaskCanceledException("the vault call timed out"));
        var key = BuildKey(rsa);

        var act = async () => await SigningSelfTest.RunAsync(signer, key, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_unavailable");
    }

    private static SigningKey BuildKey(RSA rsa) =>
        new(new SourceKeyId("current"), "kid", SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.MinValue, DateTimeOffset.MaxValue);

    private static SigningKey BuildKey(ECDsa ec) =>
        new(new SourceKeyId("current"), "kid", SigningAlgorithm.ES256, PublicKeyParameters.FromEc(ec.ExportParameters(false)), DateTimeOffset.MinValue, DateTimeOffset.MaxValue);

    private sealed class EcSigner(ECDsa ec) : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>>(ec.SignData(signingInput.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        public void Dispose()
        {
        }
    }

    private sealed class GarbageSigner : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            Task.FromResult<ReadOnlyMemory<byte>>(new byte[] { 1, 2, 3 });

        public void Dispose()
        {
        }
    }

    private sealed class ThrowingSigner(Exception exception) : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default) =>
            throw exception;

        public void Dispose()
        {
        }
    }
}
