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
}
