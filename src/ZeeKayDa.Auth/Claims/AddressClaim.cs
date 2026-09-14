namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The OpenID Connect <c>address</c> claim (OpenID Connect Core §5.1.1). Every member is
/// optional; a <see langword="null"/> member is omitted from the wire form.
/// </summary>
/// <remarks>
/// Converts implicitly to <see cref="ClaimValue"/>, which writes the standard member names
/// (<c>street_address</c>, <c>postal_code</c>, and so on) itself, so no serializer setting can
/// change the wire form of the one standard object claim.
/// </remarks>
public sealed record AddressClaim
{
    /// <summary>The full mailing address, formatted for display or on a label.</summary>
    public string? Formatted { get; init; }

    /// <summary>The street address component, which may span several lines separated by newlines.</summary>
    public string? StreetAddress { get; init; }

    /// <summary>The city or locality.</summary>
    public string? Locality { get; init; }

    /// <summary>The state, province, prefecture or region.</summary>
    public string? Region { get; init; }

    /// <summary>The zip or postal code.</summary>
    public string? PostalCode { get; init; }

    /// <summary>The country name.</summary>
    public string? Country { get; init; }
}
