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
public readonly record struct SigningOutcome(ReadOnlyMemory<byte> SigningInput, ReadOnlyMemory<byte> Signature, SigningKey Key);
