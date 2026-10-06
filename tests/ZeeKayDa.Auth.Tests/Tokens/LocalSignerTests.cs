using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

        var act = () => sut.SignAsync(new byte[] { 1 }, ct);

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public void FromCertificate_rejects_an_undefined_algorithm_before_opening_the_private_key()
    {
        using var certificate = SelfSigned(RSA.Create(2048));

        var act = () => LocalSigner.FromCertificate(certificate, (SigningAlgorithm)999);

        act.Should().Throw<ArgumentOutOfRangeException>().Which.ParamName.Should().Be("algorithm");
    }

    [Fact]
    public async Task FromCertificate_signs_a_payload_that_verifies_with_an_RSA_certificates_public_key()
    {
        using var certificate = SelfSigned(RSA.Create(2048));
        using var sut = LocalSigner.FromCertificate(certificate, SigningAlgorithm.RS256);
        var input = new byte[] { 1, 2, 3, 4, 5 };

        var signature = await sut.SignAsync(input, TestContext.Current.CancellationToken);

        using var publicKey = certificate.GetRSAPublicKey()!;
        publicKey.VerifyData(input, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public async Task FromCertificate_signs_a_payload_that_verifies_with_an_EC_certificates_public_key()
    {
        using var certificate = SelfSigned(ECDsa.Create(ECCurve.NamedCurves.nistP256));
        using var sut = LocalSigner.FromCertificate(certificate, SigningAlgorithm.ES256);
        var input = new byte[] { 1, 2, 3, 4, 5 };

        var signature = await sut.SignAsync(input, TestContext.Current.CancellationToken);

        using var publicKey = certificate.GetECDsaPublicKey()!;
        publicKey.VerifyData(input, signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public async Task FromCertificate_signer_keeps_signing_after_the_certificate_is_disposed()
    {
        var certificate = SelfSigned(RSA.Create(2048));
        using var publicKey = certificate.GetRSAPublicKey()!;
        using var sut = LocalSigner.FromCertificate(certificate, SigningAlgorithm.RS256);
        certificate.Dispose();
        var input = new byte[] { 9, 8, 7 };

        var signature = await sut.SignAsync(input, TestContext.Current.CancellationToken);

        publicKey.VerifyData(input, signature.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .Should().BeTrue();
    }

    [Fact]
    public void FromCertificate_throws_private_key_not_found_for_a_certificate_without_a_private_key()
    {
        using var withKey = SelfSigned(RSA.Create(2048));
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));

        var act = () => LocalSigner.FromCertificate(publicOnly, SigningAlgorithm.RS256);

        act.Should().Throw<ZeeKayDaConfigurationException>().Which.AggregatedFailures
            .Should().ContainSingle(f => f.Code == "signing.certificate.private_key_not_found");
    }

    private static X509Certificate2 SelfSigned(RSA rsa)
    {
        using (rsa)
        {
            var request = new CertificateRequest("CN=local-signer-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(30));
        }
    }

    private static X509Certificate2 SelfSigned(ECDsa ecdsa)
    {
        using (ecdsa)
        {
            var request = new CertificateRequest("CN=local-signer-test", ecdsa, HashAlgorithmName.SHA256);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(30));
        }
    }
}
