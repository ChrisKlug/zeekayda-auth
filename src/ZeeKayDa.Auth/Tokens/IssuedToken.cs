namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A token an <see cref="ITokenIssuer"/> has issued.
/// </summary>
/// <remarks>
/// <see cref="Value"/> is the token as handed to the client: a compact JWS, or an opaque handle. It carries
/// no expiry, which is already a claim in the payload, and no <c>token_type</c>, which is the token
/// endpoint's concern.
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

    // Never the token: the sanitizing logger redacts by placeholder name, so a logged IssuedToken
    // would otherwise reach the sink verbatim.
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"{nameof(Value)} = <{_value.Length} chars>, {nameof(Kind)} = {Kind}");
        return true;
    }
}
