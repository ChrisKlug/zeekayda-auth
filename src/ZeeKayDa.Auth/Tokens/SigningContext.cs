namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The key an <see cref="ISigningKeyRing"/> has resolved to sign with, handed to the
/// <c>buildSigningInput</c> callback passed to <see cref="ISigningKeyRing.SignAsync{TState}"/>.
/// </summary>
public readonly struct SigningContext
{
    private readonly SigningKey? _key;

    internal SigningContext(SigningKey key) => _key = key;

    /// <summary>Gets the key that will sign.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance is <see langword="default"/>(<see cref="SigningContext"/>) rather
    /// than one obtained from <see cref="ISigningKeyRing.SignAsync{TState}"/>.
    /// </exception>
    public SigningKey Key => _key ?? throw new InvalidOperationException(
        $"{nameof(SigningContext)} was default-initialized; it must be obtained from a " +
        $"{nameof(ISigningKeyRing)}.{nameof(ISigningKeyRing.SignAsync)} callback.");
}
