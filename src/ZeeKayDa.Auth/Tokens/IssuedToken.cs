namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A token an <see cref="ITokenIssuer"/> has issued.
/// </summary>
/// <param name="Value">
/// The token exactly as it is handed to the client — a compact JWS serialization for a JWT
/// issuer, an opaque handle for a reference-token issuer.
/// </param>
/// <param name="Kind">
/// The kind that was requested, echoed back so an issuer registered under the wrong
/// <see cref="TokenKind"/> key is detectable at the call site.
/// </param>
/// <remarks>
/// Deliberately not carrying <c>ExpiresAt</c> or <c>token_type</c>: expiry is a claim the caller
/// already put in the payload, so returning it here would create a second place for the same fact
/// to be wrong, and <c>token_type</c> is a token-endpoint response concern, not an issuance one.
/// </remarks>
public sealed record IssuedToken(string Value, TokenKind Kind)
{
    // The synthesized PrintMembers would print Value — a live bearer token — and the sanitizing
    // logger redacts by placeholder name, so a logged IssuedToken would reach the sink verbatim.
    // Print the kind and length only; the token itself never appears in ToString().
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"{nameof(Value)} = <{Value.Length} chars>, {nameof(Kind)} = {Kind}");
        return true;
    }
}
