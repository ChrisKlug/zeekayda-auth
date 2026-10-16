using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The session subject of an external principal, derived from the provider's registration name,
/// the subject claim's issuer and the upstream value: upstream subjects are unique only per issuer.
/// </summary>
public static class ExternalSubject
{
    /// <summary>The claims the upstream subject is read from, in order.</summary>
    internal static readonly string[] SubjectClaimTypes = ["sub", ClaimTypes.NameIdentifier];

    /// <summary>The provider's claims with the upstream subject replaced by the derived one.</summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The principal carries no subject claim, or its subject claim names no issuer.
    /// </exception>
    internal static ClaimsPrincipal ForPromotion(string providerId, ClaimsPrincipal principal)
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
                "are unique only within their issuer, so the session subject is derived from the provider, " +
                "the issuer and the subject together. Create the claim with its issuer set.");
        }

        var claims = new List<Claim> { new("sub", Derive(providerId, subject.Issuer, subject.Value)) };
        claims.AddRange(principal.Claims.Where(claim =>
            !SubjectClaimTypes.Contains(claim.Type, StringComparer.OrdinalIgnoreCase)));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, providerId));
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
    /// Use it to link a local account to an external user before they first sign in, or to move
    /// users across a renamed provider registration: the registration name is part of the result,
    /// so renaming one gives every user who signed in through it a new subject.
    /// </para>
    /// <para>
    /// Every part is compared exactly, case included. The result is
    /// <c>base64url(SHA-256(length-prefixed provider, issuer, subject))</c>, so no two inputs collide
    /// on a separator.
    /// </para>
    /// </remarks>
    /// <param name="providerId">The provider's registration name, as given to <c>WithProviders</c>.</param>
    /// <param name="issuer">The issuer of the provider's subject claim (<see cref="Claim.Issuer"/>).</param>
    /// <param name="subject">The user's subject at the provider: the value of its <c>sub</c> or name-identifier claim.</param>
    /// <returns>The derived subject, 43 URL-safe characters.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="providerId"/>, <paramref name="issuer"/> or <paramref name="subject"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="providerId"/>, <paramref name="issuer"/> or <paramref name="subject"/> is empty.
    /// </exception>
    public static string Derive(string providerId, string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(providerId);
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(providerId);
            writer.Write(issuer);
            writer.Write(subject);
        }

        return WebEncoders.Base64UrlEncode(SHA256.HashData(buffer.ToArray()));
    }
}
