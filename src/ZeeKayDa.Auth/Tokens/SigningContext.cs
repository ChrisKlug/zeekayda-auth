namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The key a <see cref="SigningKeyRing"/> has resolved to sign with, handed to the
/// <c>buildSigningInput</c> callback passed to <see cref="SigningKeyRing.SignAsync{TState}"/>.
/// </summary>
public readonly struct SigningContext
{
    private readonly SigningKey? _key;

    internal SigningContext(SigningKey key) => _key = key;

    /// <summary>Gets the key that will sign.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance is <see langword="default"/>(<see cref="SigningContext"/>) rather
    /// than one obtained from <see cref="SigningKeyRing.SignAsync{TState}"/>.
    /// </exception>
    public SigningKey Key => _key ?? throw new InvalidOperationException(
        $"{nameof(SigningContext)} was default-initialized; it must be obtained from a " +
        $"{nameof(SigningKeyRing)}.{nameof(SigningKeyRing.SignAsync)} callback.");
}
