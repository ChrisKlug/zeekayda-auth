using System.Buffers.Text;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Proves a freshly opened <see cref="ISigner"/>'s private key pairs with the public key it signs for.</summary>
/// <remarks>
/// The payload carries a fresh nonce, so a signer returning a cached signature fails, and is not shaped
/// like a JWS, so a leaked self-test signature can never pass for one.
/// </remarks>
internal static class SigningSelfTest
{
    /// <summary>Signs a fresh nonce payload with <paramref name="signer"/> and verifies it against <paramref name="key"/>.</summary>
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

        if (!TryVerify(key, payload.Span, signature.Span, out var verifierFault))
        {
            var failure = new ZeeKayDaConfigurationFailure(
                "signing.self_test_failed",
                $"The signer for key '{key.Kid}' produced a signature that does not verify " +
                "against that key's own public key. The private key materialized for signing " +
                $"does not match the public key published under this kid — refusing to serve " +
                $"tokens under '{key.Kid}'.");

            // Kept as the inner exception, so a platform failure is not diagnosed as a mismatched key.
            throw verifierFault is null
                ? new ZeeKayDaConfigurationException(failure)
                : new ZeeKayDaConfigurationException(failure, verifierFault);
        }
    }

    /// <summary>
    /// A signer that throws fails the self-test under its own code, naming the type, never a message that may
    /// carry a credential. Only the caller's own cancellation propagates.
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
        catch (Exception ex) when (!IsCallersCancellation(ex, cancellationToken))
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
    /// The caller's whenever its token was cancelled, whatever token the exception carries (a signer may link
    /// it); otherwise the signer's own timeout, and a failure.
    /// </summary>
    private static bool IsCallersCancellation(Exception ex, CancellationToken cancellationToken) =>
        ex is OperationCanceledException && cancellationToken.IsCancellationRequested;

    /// <summary>
    /// Bytes that are not a signature of the key's algorithm do not verify; a platform throw is kept for the
    /// operator, since it may be the host's crypto stack failing.
    /// </summary>
    private static bool TryVerify(SigningKey key, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, out Exception? verifierFault)
    {
        try
        {
            verifierFault = null;
            return SigningAlgorithms.Verify(key.Algorithm, key.PublicKey, payload, signature);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            verifierFault = ex;
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
