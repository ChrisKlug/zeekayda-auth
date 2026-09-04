using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The session subject of an external principal the framework promotes itself. Upstream
/// subjects are unique only within their issuer, so the subject is derived from the provider, the
/// subject claim's issuer and the upstream value together — collision-resistant, fixed-length,
/// and stable for the life of the upstream account. Two providers returning the same value can
/// never share a session, and the provider's identity is the registration name, so re-registering
/// a name keeps every subject while moving a name to a different upstream is a new provider.
/// </summary>
internal static class ExternalSubject
{
    /// <summary>
    /// The claim the upstream subject is read from, in order: <c>sub</c> from a provider that
    /// thinks in OpenID Connect, the .NET name identifier from one that maps claims.
    /// </summary>
    private static readonly string[] SubjectClaimTypes = ["sub", ClaimTypes.NameIdentifier];

    /// <summary>
    /// Builds the principal to promote: the provider's claims with the upstream subject replaced
    /// by the derived one.
    /// </summary>
    /// <exception cref="ZeeKayDaInteractionException">
    /// The principal carries no subject claim, or its subject claim names no issuer.
    /// </exception>
    public static ClaimsPrincipal ForPromotion(string providerId, ClaimsPrincipal principal)
    {
        ArgumentException.ThrowIfNullOrEmpty(providerId);
        ArgumentNullException.ThrowIfNull(principal);

        var subject = SubjectClaimTypes
            .Select(principal.FindFirst)
            .FirstOrDefault(claim => !string.IsNullOrEmpty(claim?.Value))
            ?? throw new ZeeKayDaInteractionException(
                $"The principal provider '{providerId}' returned carries no subject. A provider handler " +
                $"must add a 'sub' or '{ClaimTypes.NameIdentifier}' claim identifying the user at the provider.");

        // A JWT-validating handler stamps the token issuer, an OAuth handler stamps ClaimsIssuer,
        // and a hand-written handler sets it when it creates the claim; the default issuer names
        // no namespace, and a subject with no namespace is one line away from compliant.
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

    /// <summary>
    /// <c>base64url(SHA-256(length-prefixed provider, issuer, subject))</c>. The length prefixes
    /// leave no separator to collide on.
    /// </summary>
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
