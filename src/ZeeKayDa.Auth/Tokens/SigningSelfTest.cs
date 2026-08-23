using System.Buffers.Text;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Proves a freshly opened <see cref="ISigner"/>'s private key actually pairs with the public key
/// it claims to sign for, before it is ever used to produce a real token.
/// </summary>
/// <remarks>
/// The payload includes a fresh, per-invocation <see cref="RandomNumberGenerator"/> nonce, base64url
/// encoded, so that a compile-time-constant payload cannot pass this test merely by returning a
/// previously cached signature — a memoizing remote signer or caching signing proxy signs a
/// different payload every time this runs and fails when it returns stale bytes. The payload keeps
/// the non-JWS shape (a literal space, no <c>.</c> separator) so a leaked self-test signature could
/// never be mistaken for one.
/// </remarks>
internal static class SigningSelfTest
{
    /// <summary>
    /// Signs a fresh nonce payload with <paramref name="signer"/> and verifies the result against
    /// <paramref name="key"/>'s own public material.
    /// </summary>
    /// <param name="signer">The signer to test.</param>
    /// <param name="key">The key <paramref name="signer"/> claims to sign for.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.self_test_failed</c> when the signature does not verify
    /// against <paramref name="key"/>'s own public key.
    /// </exception>
    internal static async ValueTask RunAsync(ISigner signer, SigningKey key, CancellationToken cancellationToken)
    {
        var payload = BuildPayload();

        var signature = await signer.SignAsync(payload, cancellationToken).ConfigureAwait(false);
        var verified = SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, payload.Span, signature.Span);

        if (!verified)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.self_test_failed",
                    $"The signer for key '{key.Kid}' produced a signature that does not verify " +
                    "against that key's own public key. The private key materialized for signing " +
                    $"does not match the public key published under this kid — refusing to serve " +
                    $"tokens under '{key.Kid}'."));
        }
    }

    private static ReadOnlyMemory<byte> BuildPayload()
    {
        var nonce = RandomNumberGenerator.GetBytes(32);
        var encodedNonce = new byte[Base64Url.GetEncodedLength(nonce.Length)];
        Base64Url.EncodeToUtf8(nonce, encodedNonce);

        var prefix = "zeekayda-auth signing self-test "u8;
        var payload = new byte[prefix.Length + encodedNonce.Length];
        prefix.CopyTo(payload);
        encodedNonce.CopyTo(payload.AsSpan(prefix.Length));

        return payload;
    }
}
