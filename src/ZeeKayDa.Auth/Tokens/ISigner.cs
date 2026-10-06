namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Produces signature bytes over a formed JWS signing input for exactly one activation of one
/// signing key. Returned by <see cref="ISigningKeySource.CreateSignerAsync"/> for the key a
/// <see cref="SigningKeyRing"/> has chosen to sign with. The ring proves at startup, with a real
/// signature verified against the key's public material, that the signer signs for that key under
/// that key's algorithm.
/// </summary>
/// <remarks>
/// <see cref="ISigningKeySource.CreateSignerAsync"/> returns a new instance on every call, which the
/// caller then owns; <see cref="IDisposable.Dispose"/> releases only what this instance created, never
/// a shared client it was handed.
/// </remarks>
public interface ISigner : IDisposable
{
    /// <summary>
    /// Produces the raw signature bytes for <paramref name="signingInput"/>.
    /// </summary>
    /// <param name="signingInput">
    /// The exact bytes to sign. For a token that is the JWS signing input,
    /// <c>base64url(header) + '.' + base64url(payload)</c>; the ring's self-test also hands a signer
    /// a short non-JWS payload once at startup, so a signer must sign whatever bytes it is given
    /// rather than validate their shape.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw signature bytes in the format required by the key's algorithm.</returns>
    Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);

}
