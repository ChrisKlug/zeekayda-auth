using System.Security.Claims;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The arguments of a page's sign-in, checked and copied before anything is awaited.
/// </summary>
internal static class SessionPrincipal
{
    private const int MaxSubjectLength = 255;

    /// <summary>The principal the session is established for: the subject alone.</summary>
    public static ClaimsPrincipal Build(string subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        if (!IsWellFormedSubject(subject))
        {
            throw new ArgumentException(
                "The subject must be 1–255 printable ASCII characters (0x21–0x7E), with no space: OpenID " +
                "Connect Core §2 caps sub at 255 ASCII characters, and a subject is compared exactly.",
                nameof(subject));
        }

        return new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], ZeeKayDaCookies.Session));
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

    private static bool IsWellFormedSubject(string subject) =>
        subject.Length is > 0 and <= MaxSubjectLength && !subject.AsSpan().ContainsAnyExceptInRange('\x21', '\x7E');
}
