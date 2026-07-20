namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Produces signature bytes over a formed JWS signing input for exactly one activation of one
/// signing key. Returned by <see cref="JwtSigningService{TOptions}.CreateSignerAsync"/> for the
/// key the base class has selected as active.
/// </summary>
/// <remarks>
/// <para>
/// One behavioural method (<see cref="SignAsync"/>); async so a remote signer (Azure Key Vault, a
/// KMS, an HSM) can make a network round trip. Local providers (development, File/PEM, PFX, Windows
/// Certificate Store) construct <see cref="LocalSigner"/> in <c>CreateSignerAsync</c> rather than
/// implementing this interface themselves; only genuinely remote providers implement
/// <see cref="ISigner"/> directly. This is ADR 0011 §1's <c>SignInputAsync</c> default/override
/// split re-expressed as an object (ADR 0015 §2).
/// </para>
/// <para>
/// <b><see cref="IDisposable.Dispose"/> is a normative contract, not advisory prose.</b> The base
/// class calls <see cref="IDisposable.Dispose"/> on the previously active <see cref="ISigner"/>
/// every time the active key changes (or at shutdown). <c>Dispose</c> on an implementation of this
/// interface <b>MUST</b> release only the per-activation handle or resource this specific instance
/// introduced. A remote implementation whose <see cref="SignAsync"/> uses a shared, DI-owned SDK
/// client (an Azure Key Vault client, say) <b>MUST NOT</b> tear that shared client down on
/// <c>Dispose</c> — doing so would break every other <see cref="ISigner"/> instance, and every
/// future caller, that also depends on the same shared client. Only <see cref="LocalSigner"/>'s own
/// wrapped <see cref="System.Security.Cryptography.AsymmetricAlgorithm"/> is safe to dispose
/// unconditionally, because it is never shared with anything else (ADR 0015 §2/Security
/// Considerations item 5).
/// </para>
/// </remarks>
public interface ISigner : IDisposable
{
    /// <summary>
    /// Produces the raw signature bytes for <paramref name="signingInput"/>.
    /// </summary>
    /// <param name="signingInput">
    /// The exact bytes to sign: <c>base64url(header) + '.' + base64url(payload)</c>.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw signature bytes in the format required by the key's algorithm.</returns>
    ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);
}
