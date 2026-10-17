using System.Runtime.CompilerServices;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The arguments of a page's sign-in, checked and copied before anything is awaited.
/// </summary>
internal static class SignInArguments
{
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

    /// <summary>
    /// The login identifier, or <see langword="null"/> when none was given. A client's
    /// <c>login_hint</c> is matched against it, so it is held to the hint's own rule.
    /// </summary>
    public static string? LoginIdentifier(
        string? loginIdentifier,
        [CallerArgumentExpression(nameof(loginIdentifier))] string? paramName = null)
    {
        if (loginIdentifier is null)
            return null;

        if (string.IsNullOrWhiteSpace(loginIdentifier)
            || loginIdentifier.Length > AuthorizeRequestValidator.MaxLoginHintLength
            || loginIdentifier.EnumerateRunes().Any(AuthorizeRequestValidator.IsRefusedInLoginHint))
        {
            throw new ArgumentException(
                "The login identifier must be 1–256 characters, not blank, with no control, line-separator "
                + "or invisible formatting character: the rule a client's login_hint is held to, since one "
                + "is matched against the other. Pass null to use the subject.",
                paramName);
        }

        return loginIdentifier;
    }
}
