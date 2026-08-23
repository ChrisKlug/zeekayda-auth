namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The key an <see cref="ISigningKeyRing"/> has resolved to sign with, handed to the
/// <c>buildSigningInput</c> callback passed to <see cref="ISigningKeyRing.SignAsync{TState}"/>.
/// </summary>
public readonly struct SigningContext
{
    internal SigningContext(SigningKey key) => Key = key;

    /// <summary>Gets the key that will sign.</summary>
    public SigningKey Key { get; }
}
