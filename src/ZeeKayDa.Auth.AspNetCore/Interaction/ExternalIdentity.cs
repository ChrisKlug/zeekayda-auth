namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Who the user is at an external provider: the upstream subject, and the issuer that makes it
/// unique. The key to look a linked local account up by.
/// </summary>
/// <remarks>
/// <para>
/// Link on the issuer and subject together: upstream subjects are unique only within their
/// issuer. <see cref="ExternalSubject.Derive"/> turns the pair into the subject an unlinked
/// external sign-in gets.
/// </para>
/// <para>
/// <strong>Linking on the provider's <c>email</c> is an account-takeover risk</strong> unless the
/// provider asserts <c>email_verified</c> and you trust its verification; a missing claim means
/// unverified. Treat an email match as a prompt to prove ownership of the local account, never as
/// a link.
/// </para>
/// </remarks>
public sealed class ExternalIdentity
{
    internal ExternalIdentity(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        Issuer = issuer;
        Subject = subject;
    }

    /// <summary>
    /// The issuer of the provider's subject claim (<see cref="System.Security.Claims.Claim.Issuer"/>),
    /// never an <c>iss</c> claim: the OpenID Connect handler stamps the token's issuer, an OAuth
    /// handler its <c>ClaimsIssuer</c>, which defaults to the scheme name.
    /// </summary>
    public string Issuer { get; }

    /// <summary>The user's subject at the provider: its <c>sub</c> or name-identifier claim.</summary>
    public string Subject { get; }
}
