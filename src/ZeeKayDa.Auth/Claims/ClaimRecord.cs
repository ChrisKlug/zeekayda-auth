namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// One claim name with one value, as an <see cref="IClaimsProvider"/> returns it.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Type"/> is the OpenID Connect wire name, <c>email</c> or <c>given_name</c>, never a
/// <c>ClaimTypes</c> URI. A provider returns one record per value: three <c>role</c> records
/// become <c>"role": ["admin", "editor", "viewer"]</c> on the wire, in that order.
/// </para>
/// <para>
/// The constructor is the one place a claim is validated. It refuses a blank type and a value a
/// token could not carry, naming the claim type and never the value. A record that exists is a
/// record that can be written; nothing downstream checks again. The default value of this struct
/// is the exception: its members throw, and a result containing one is treated as a provider bug.
/// </para>
/// </remarks>
public readonly record struct ClaimRecord
{
    private readonly string? _type;
    private readonly ClaimValue _value;

    /// <summary>Initializes a record of <paramref name="type"/> carrying <paramref name="value"/>.</summary>
    /// <param name="type">The claim's wire name.</param>
    /// <param name="value">The claim's value.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="type"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="type"/> is empty or white space, or when <paramref name="value"/>
    /// is one a token cannot carry: the default <see cref="ClaimValue"/>, a <see langword="null"/>
    /// string, an empty string, <see cref="double.NaN"/>, an infinity, or JSON <c>null</c>.
    /// </exception>
    public ClaimRecord(string type, ClaimValue value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);

        if (!value.IsRepresentable)
        {
            throw new ArgumentException(
                $"Claim '{type}' has no value a token can carry. A claim value must not be null, an empty " +
                "string, NaN, infinite or a default ClaimValue; an unavailable claim is expressed by not " +
                "returning the record.",
                nameof(value));
        }

        _type = type;
        _value = value;
    }

    /// <summary>The claim's wire name.</summary>
    /// <exception cref="InvalidOperationException">This is the default <see cref="ClaimRecord"/>.</exception>
    public string Type => _type ?? throw DefaultRecord();

    /// <summary>The claim's value.</summary>
    /// <exception cref="InvalidOperationException">This is the default <see cref="ClaimRecord"/>.</exception>
    public ClaimValue Value => _type is null ? throw DefaultRecord() : _value;

    /// <summary>Names the claim type and the value's JSON kind, never the value.</summary>
    public override string ToString() => _type is null ? "ClaimRecord(default)" : $"ClaimRecord({_type}: {_value})";

    internal bool IsDefault => _type is null;

    private static InvalidOperationException DefaultRecord() =>
        new("This is the default ClaimRecord, which names no claim. Construct records through the constructor.");
}
