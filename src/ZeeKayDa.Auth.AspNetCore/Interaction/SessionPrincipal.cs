using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The arguments of a page's sign-in, checked and copied before anything is awaited.
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
    /// A copy of the page's additional claims, reserved ones stripped; a subject claim is refused,
    /// not silently dropped.
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
    /// A copy of the authentication methods, refused here so the blame lands on the caller's argument.
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
