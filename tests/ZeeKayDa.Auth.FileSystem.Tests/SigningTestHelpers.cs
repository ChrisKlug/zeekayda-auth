using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Test-only base64url helpers and end-to-end JWS signature verification, so tests can prove a
/// <see cref="SigningResult"/> produced by <see cref="IJwtSigningService.SignAsync"/> actually
/// verifies against the corresponding <see cref="SigningKeyDescriptor"/>'s public key — without
/// depending on the internal <c>SigningAlgorithms</c> class (not visible outside
/// <c>ZeeKayDa.Auth</c>).
/// </summary>
internal static class SigningTestHelpers
{
    public static byte[] Base64UrlEncode(byte[] raw) =>
        Encoding.ASCII.GetBytes(Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_'));

    public static byte[] Base64UrlDecode(ReadOnlyMemory<byte> segment)
    {
        var text = Encoding.ASCII.GetString(segment.Span).Replace('-', '+').Replace('_', '/');
        text = (text.Length % 4) switch
        {
            2 => text + "==",
            3 => text + "=",
            _ => text,
        };
        return Convert.FromBase64String(text);
    }

    /// <summary>
    /// Verifies an RS256-signed <see cref="SigningResult"/> against the RSA public key carried by
    /// <paramref name="descriptor"/>.
    /// </summary>
    public static bool VerifyRsaSignature(SigningKeyDescriptor descriptor, SigningResult result, byte[] payloadSegment)
    {
        descriptor.Algorithm.Should().Be(SigningAlgorithm.RS256, "this helper only verifies the RS256 signature shape");

        using var rsa = RSA.Create(descriptor.RsaPublicParameters!.Value);
        var signingInput = BuildSigningInput(result.HeaderSegment, payloadSegment);
        var signature = Base64UrlDecode(result.SignatureSegment);

        return rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static byte[] BuildSigningInput(ReadOnlyMemory<byte> headerSegment, byte[] payloadSegment)
    {
        var result = new byte[headerSegment.Length + 1 + payloadSegment.Length];
        headerSegment.Span.CopyTo(result);
        result[headerSegment.Length] = (byte)'.';
        payloadSegment.CopyTo(result.AsSpan(headerSegment.Length + 1));
        return result;
    }
}
