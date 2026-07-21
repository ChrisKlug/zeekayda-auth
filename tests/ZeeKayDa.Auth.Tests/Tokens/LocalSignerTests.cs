using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class LocalSignerTests
{
    [Fact]
    public void Constructor_throws_when_privateKey_is_null()
    {
        var act = () => new LocalSigner(SigningAlgorithm.RS256, null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("privateKey");
    }

    [Fact]
    public async Task SignAsync_produces_a_signature_verifiable_with_the_corresponding_public_key()
    {
        var rsa = RSA.Create(2048);
        var sut = new LocalSigner(SigningAlgorithm.RS256, rsa);
        var input = new byte[] { 1, 2, 3, 4, 5 };
        var ct = TestContext.Current.CancellationToken;

        var signature = await sut.SignAsync(input, ct);

        rsa.VerifyData(input, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();

        sut.Dispose();
    }

    [Fact]
    public void Dispose_disposes_the_wrapped_private_key()
    {
        using var innerRsa = RSA.Create(2048);
        var trackingRsa = new DisposeTrackingRsa(innerRsa);
        var sut = new LocalSigner(SigningAlgorithm.RS256, trackingRsa);

        sut.Dispose();

        trackingRsa.DisposeCount.Should().Be(1, "LocalSigner must dispose the private key it was constructed with");
    }

    /// <summary>
    /// A minimal RSA wrapper that delegates every real operation to an inner key but counts
    /// <see cref="Dispose(bool)"/> calls, so a test can assert <see cref="LocalSigner.Dispose"/>
    /// disposes the wrapped key without depending on platform-specific post-dispose exception
    /// behaviour of the real BCL RSA implementation.
    /// </summary>
    private sealed class DisposeTrackingRsa : RSA
    {
        private readonly RSA _inner;

        public DisposeTrackingRsa(RSA inner)
        {
            _inner = inner;
        }

        public int DisposeCount { get; private set; }

        public override RSAParameters ExportParameters(bool includePrivateParameters) => _inner.ExportParameters(includePrivateParameters);

        public override void ImportParameters(RSAParameters parameters) => _inner.ImportParameters(parameters);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                DisposeCount++;

            base.Dispose(disposing);
        }
    }

    [Fact]
    public void Dispose_is_safe_to_call_multiple_times()
    {
        var rsa = RSA.Create(2048);
        var sut = new LocalSigner(SigningAlgorithm.RS256, rsa);

        var act = () =>
        {
            sut.Dispose();
            sut.Dispose();
        };

        act.Should().NotThrow();
    }

    [Fact]
    public async Task SignAsync_throws_ObjectDisposedException_after_Dispose()
    {
        var rsa = RSA.Create(2048);
        var sut = new LocalSigner(SigningAlgorithm.RS256, rsa);
        sut.Dispose();
        var ct = TestContext.Current.CancellationToken;

        var act = () => sut.SignAsync(new byte[] { 1 }, ct).AsTask();

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }
}
