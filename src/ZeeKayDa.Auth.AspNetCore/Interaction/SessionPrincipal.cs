using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The arguments of a page's sign-in, checked and copied before anything is awaited: what was
/// validated is what is signed in, whatever the caller does to its own arrays or claims afterwards.
/// </summary>
internal static class SessionPrincipal
{
    /// <summary>The principal the session is established for: the subject and the page's additional claims.</summary>
    public static ClaimsPrincipal Build(string subject, Claim[] additionalClaims)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var claims = AdditionalClaims(additionalClaims);

        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject), .. claims], ZeeKayDaCookies.Session));
    }

    /// <summary>
    /// A copy of the page's additional claims with the reserved ones stripped. The subject is
    /// refused rather than dropped: a page passing one expects it to be used, and silently
    /// ignoring it would hide the mistake.
    /// </summary>
    public static Claim[] AdditionalClaims(Claim[] additionalClaims)
    {
        ArgumentNullException.ThrowIfNull(additionalClaims);

        if (additionalClaims.Any(claim => claim is null))
            throw new ArgumentException("An entry in the additional claims is null.", nameof(additionalClaims));

        if (additionalClaims.Any(claim => ExternalSubject.IsSubjectClaimType(claim.Type)))
        {
            throw new ArgumentException(
                "An additional claim names the subject. The subject is the framework's to set: pass it as " +
                "the subject argument of LoginInteraction.SignInAsync or SignInWithReplacedAccountAsync, " +
                "and ProviderSignInInteraction.SignInAsync derives it from the provider.",
                nameof(additionalClaims));
        }

        return additionalClaims
            .Where(claim => !ReservedClaims.IsReserved(claim))
            .Select(ReservedClaims.Materialize)
            .ToArray();
    }

    /// <summary>
    /// A copy of the authentication methods. Refused here rather than at the claim write, so the
    /// blame lands on the caller's argument, not on a malformed session cookie several frames later.
    /// </summary>
    public static string[] Methods(IEnumerable<string> authenticationMethods)
    {
        ArgumentNullException.ThrowIfNull(authenticationMethods);

        var methods = authenticationMethods.ToArray();
        if (methods.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "An authentication method reference is null or blank. Pass a value such as "
                + "AuthenticationMethods.Password, or pass [] to omit the amr claim.",
                nameof(authenticationMethods));

        return methods;
    }
}
