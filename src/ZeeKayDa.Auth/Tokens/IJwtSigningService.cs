namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Supplies the authorization server's currently trusted signing keys and performs
/// signatures over JWS input. The active signing key and algorithm are selected by the
/// implementation; callers never choose a key or algorithm and never hold private key
/// material.
/// </summary>
/// <remarks>
/// <para>
/// Implementations of this interface are responsible for selecting the active key, building
/// the JWS header, and returning both the encoded header and signature as a
/// <see cref="SigningResult"/>. The caller (<c>ITokenWriter</c>) only assembles the compact JWS:
/// <c>header "." payload "." signature</c>.
/// </para>
/// <para>
/// The async design preserves forward compatibility for remote signing providers (KMS / HSM /
/// Azure Key Vault) where every <see cref="SignAsync"/> call involves network I/O.
/// </para>
/// </remarks>
public interface IJwtSigningService
{
    /// <summary>
    /// Returns every currently trusted signing key — the active key plus any keys still inside
    /// their retirement/overlap window. Excludes fully retired keys and not-yet-activated keys.
    /// These are exactly the keys that must appear in the JWKS.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs the supplied base64url-encoded payload segment. The service constructs the JWS
    /// header internally, forms the signing input, signs, and returns the pre-encoded header
    /// and signature segments. The caller assembles <c>header "." payload "." signature</c>.
    /// </summary>
    /// <param name="payloadSegment">
    /// The base64url-encoded payload segment. The caller must have already base64url-encoded the
    /// raw claims bytes before passing them here.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default);
}
