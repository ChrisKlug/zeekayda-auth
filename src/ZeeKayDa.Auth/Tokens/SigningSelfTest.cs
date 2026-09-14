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
    /// against <paramref name="key"/>'s own public key, or is not a signature at all; and with
    /// <c>signing.self_test_unavailable</c> when the signer throws, naming the exception type only
    /// and carrying the original as the inner exception.
    /// </exception>
    internal static async ValueTask RunAsync(ISigner signer, SigningKey key, CancellationToken cancellationToken)
    {
        var payload = BuildPayload();

        var signature = await SignAsync(signer, key, payload, cancellationToken).ConfigureAwait(false);

        if (!Verifies(key, payload.Span, signature.Span))
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

    /// <summary>
    /// The signer is caller-supplied code, and a self-test it cannot complete aborts the handoff
    /// exactly as a mismatch does, under its own code. The exception type is named, never its
    /// message, which for a remote signer may carry a request URL or credential; a source's own
    /// configuration exception already carries a published code and passes through verbatim.
    /// </summary>
    private static async ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ISigner signer, SigningKey key, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        try
        {
            return await signer.SignAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        catch (ZeeKayDaConfigurationException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.self_test_unavailable",
                    $"The signer for key '{key.Kid}' threw {ex.GetType().FullName} during the signing self-test, " +
                    $"so the key could not be proven to pair with its published public key — refusing to serve " +
                    $"tokens under '{key.Kid}'. See the inner exception for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Bytes that are not a signature of this key's algorithm at all, wrong length included, do
    /// not verify; some platforms report that by throwing rather than returning false.
    /// </summary>
    private static bool Verifies(SigningKey key, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        try
        {
            return SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, payload, signature);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return false;
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
