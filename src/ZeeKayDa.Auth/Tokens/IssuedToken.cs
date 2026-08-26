namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A token an <see cref="ITokenIssuer"/> has issued.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Value"/> is the token exactly as it is handed to the client — a compact JWS
/// serialization for a JWT issuer, an opaque handle for a reference-token issuer.
/// <see cref="Kind"/> is the kind that was requested, echoed back by the issuer.
/// </para>
/// <para>
/// Deliberately not carrying <c>ExpiresAt</c> or <c>token_type</c>: expiry is a claim the caller
/// already put in the payload, so returning it here would create a second place for the same fact
/// to be wrong, and <c>token_type</c> is a token-endpoint response concern, not an issuance one.
/// </para>
/// </remarks>
public sealed record IssuedToken
{
    private readonly string _value;

    /// <summary>
    /// Initializes a new instance of the <see cref="IssuedToken"/> class.
    /// </summary>
    /// <param name="Value">The token, exactly as handed to the client.</param>
    /// <param name="Kind">The kind that was requested.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="Value"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="Value"/> is empty — an empty token on the wire is never right.
    /// </exception>
    public IssuedToken(string Value, TokenKind Kind)
    {
        ArgumentException.ThrowIfNullOrEmpty(Value);
        _value = Value;
        this.Kind = Kind;
    }

    /// <summary>Gets the token, exactly as handed to the client.</summary>
    public string Value
    {
        get => _value;
        init
        {
            ArgumentException.ThrowIfNullOrEmpty(value);
            _value = value;
        }
    }

    /// <summary>Gets the kind that was requested, echoed back by the issuer.</summary>
    public TokenKind Kind { get; init; }

    /// <summary>Deconstructs this token into its value and kind.</summary>
    /// <param name="Value">The token, exactly as handed to the client.</param>
    /// <param name="Kind">The kind that was requested.</param>
    public void Deconstruct(out string Value, out TokenKind Kind)
    {
        Value = _value;
        Kind = this.Kind;
    }

    // The synthesized PrintMembers would print Value — a live bearer token — and the sanitizing
    // logger redacts by placeholder name, so a logged IssuedToken would reach the sink verbatim.
    // Print the kind and length only; the token itself never appears in ToString().
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"{nameof(Value)} = <{_value.Length} chars>, {nameof(Kind)} = {Kind}");
        return true;
    }
}
