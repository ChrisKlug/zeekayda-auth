namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The result of <see cref="ISigningKeyRing.SignAsync{TState}"/>: the exact bytes that were signed,
/// the resulting signature, and the key that signed them.
/// </summary>
/// <param name="SigningInput">
/// The exact bytes the <c>buildSigningInput</c> callback produced and that were signed — for a JWS,
/// <c>base64url(header) + '.' + base64url(payload)</c>, so the caller can assemble the final token
/// as <c>SigningInput + '.' + base64url(Signature)</c> with no rebuild and no mismatch risk.
/// </param>
/// <param name="Signature">The raw signature bytes.</param>
/// <param name="Key">The key that signed <paramref name="SigningInput"/>.</param>
public readonly record struct SigningOutcome(ReadOnlyMemory<byte> SigningInput, ReadOnlyMemory<byte> Signature, SigningKey Key)
{
    private readonly SigningKey? _key = Key;

    /// <summary>Gets the key that signed <see cref="SigningInput"/>.</summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when this instance is <see langword="default"/>(<see cref="SigningOutcome"/>) rather
    /// than one returned by <see cref="ISigningKeyRing.SignAsync{TState}"/>.
    /// </exception>
    public SigningKey Key
    {
        get => _key ?? throw new InvalidOperationException(
            $"{nameof(SigningOutcome)} was default-initialized; it must be obtained from " +
            $"{nameof(ISigningKeyRing)}.{nameof(ISigningKeyRing.SignAsync)}.");
        init => _key = value;
    }

    // The record's synthesized PrintMembers reads Key, so ToString() on a default instance would
    // throw from the guard above — a debugger watch or a log line is the last place that should
    // fail. Print the default as such instead.
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        if (_key is null)
        {
            builder.Append("<default>");
            return true;
        }

        builder.Append($"{nameof(SigningInput)} = {SigningInput.Length} bytes, ");
        builder.Append($"{nameof(Signature)} = {Signature.Length} bytes, ");
        builder.Append($"{nameof(Key)} = {_key.Kid}");
        return true;
    }
}
