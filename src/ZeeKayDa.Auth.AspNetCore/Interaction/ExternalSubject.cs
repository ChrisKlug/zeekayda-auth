using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The session subject of an external principal, derived from the subject claim's issuer and the
/// upstream value: upstream subjects are unique only per issuer.
/// </summary>
public static class ExternalSubject
{
    /// <summary>The claims the upstream subject is read from, in order.</summary>
    internal static readonly string[] SubjectClaimTypes = ["sub", ClaimTypes.NameIdentifier];

    /// <summary>The session principal for an external one: the derived subject, none of the provider's claims.</summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The principal carries no subject claim, or its subject claim names no issuer.
    /// </exception>
    internal static ClaimsPrincipal ForPromotion(string providerId, ClaimsPrincipal principal)
    {
        var identity = Identify(providerId, principal);

        return SessionPrincipal.Build(Derive(identity.Issuer, identity.Subject));
    }

    /// <summary>The upstream identity of a principal the framework will promote or park.</summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The principal carries no subject claim, or its subject claim names no issuer.
    /// </exception>
    internal static ExternalIdentity Identify(string providerId, ClaimsPrincipal principal)
    {
        ArgumentException.ThrowIfNullOrEmpty(providerId);
        ArgumentNullException.ThrowIfNull(principal);

        var subject = FindSubject(principal)
            ?? throw new ZeeKayDaInteractionException(
                $"The principal provider '{providerId}' returned carries no subject on an authenticated " +
                $"identity. A provider handler must add a 'sub' or '{ClaimTypes.NameIdentifier}' claim " +
                "identifying the user at the provider.");

        // Every stock handler stamps an issuer; the default one names no namespace to derive from.
        if (string.Equals(subject.Issuer, ClaimsIdentity.DefaultIssuer, StringComparison.Ordinal))
        {
            throw new ZeeKayDaInteractionException(
                $"The subject claim provider '{providerId}' returned names no issuer. Upstream subjects " +
                "are unique only within their issuer, so the session subject is derived from the issuer and " +
                "the subject together. Create the claim with its issuer set.");
        }

        return new ExternalIdentity(subject.Issuer, subject.Value);
    }

    /// <summary>The upstream subject claim, read only from an authenticated identity, never an auxiliary one.</summary>
    internal static Claim? FindSubject(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var authenticated = principal.Identities.Where(identity => identity.IsAuthenticated).ToArray();
        return SubjectClaimTypes
            .Select(type => authenticated
                .Select(identity => identity.FindFirst(type))
                .FirstOrDefault(claim => !string.IsNullOrEmpty(claim?.Value)))
            .FirstOrDefault(claim => claim is not null);
    }

    /// <summary>Whether <paramref name="claimType"/> names the subject, compared as claims are looked up.</summary>
    internal static bool IsSubjectClaimType(string claimType) => SubjectClaimTypes.Contains(claimType, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The <c>sub</c> a user signing in through an external provider gets: the value relying parties
    /// see for them, computed without a sign-in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The issuer namespaces the upstream subject, so the provider's registration name plays no
    /// part: two registrations of one issuer share their users' identities, and renaming a
    /// registration changes no subject. Use it to compute the subject an external user will get, to
    /// link a local account to them before they first sign in.
    /// </para>
    /// <para>
    /// Both parts are compared exactly, case included. The result is
    /// <c>base64url(SHA-256(length-prefixed issuer, subject))</c>, so no two inputs collide on a
    /// separator.
    /// </para>
    /// </remarks>
    /// <param name="issuer">The issuer of the provider's subject claim (<see cref="Claim.Issuer"/>).</param>
    /// <param name="subject">The user's subject at the provider: the value of its <c>sub</c> or name-identifier claim.</param>
    /// <returns>The derived subject, 43 URL-safe characters.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="issuer"/> or <paramref name="subject"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="issuer"/> or <paramref name="subject"/> is empty.
    /// </exception>
    public static string Derive(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(issuer);
            writer.Write(subject);
        }

        return WebEncoders.Base64UrlEncode(SHA256.HashData(buffer.ToArray()));
    }
}
