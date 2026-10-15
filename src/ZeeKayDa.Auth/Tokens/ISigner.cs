namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Signs for one activation of one key, as returned by <see cref="ISigningKeySource.CreateSignerAsync"/>.
/// The ring self-tests it against the key's public material before it signs.
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
    /// The exact bytes to sign: a JWS signing input, or the self-test's non-JWS payload, so sign
    /// whatever is given rather than validate its shape.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw signature bytes in the format required by the key's algorithm.</returns>
    Task<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);

}
