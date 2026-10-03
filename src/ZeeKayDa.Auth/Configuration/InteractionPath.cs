namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates a host-relative interaction path (such as
/// <c>AuthorizationEndpoint.Interaction.ErrorPath</c>) before it can be used as a redirect
/// destination.
/// </summary>
/// <remarks>
/// These paths are where the framework sends a user when an error cannot be redirected to the
/// client, so a malformed one would turn the safety net into the open redirect it exists to
/// avoid. Rejecting the dangerous shapes at startup keeps that a configuration failure rather
/// than a runtime surprise.
/// </remarks>
internal static class InteractionPath
{
    /// <summary>
    /// The failure for <paramref name="path"/> under <paramref name="code"/> when it is set and not
    /// <see cref="IsSafe"/>. Each of these is a redirect destination the framework builds itself.
    /// </summary>
    public static IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? path, string optionPath, string code)
    {
        if (path is null || IsSafe(path))
            yield break;

        yield return new(
            code,
            $"AuthorizationServerOptions.{optionPath} must be an " +
            "absolute path within the host application (starting with '/'), without scheme, " +
            "authority, query, fragment, control characters, or a leading '//' or '/\\' " +
            "that a browser would resolve to another origin.");
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="path"/> is an absolute path within the
    /// host application, with no scheme, authority, query, or fragment, and nothing a browser
    /// would normalise into another origin.
    /// </summary>
    public static bool IsSafe(string path)
    {
        if (!path.StartsWith('/'))
            return false;

        // Browsers strip tab/CR/LF from a URL before resolving it, so a control character can
        // turn "/<tab>/evil.com" into the protocol-relative "//evil.com".
        if (path.Any(char.IsControl))
            return false;

        if (EscapesToAnotherOrigin(path))
            return false;

        if (HasQueryOrFragment(path))
            return false;

        return Uri.TryCreate(path, UriKind.Relative, out _);
    }

    /// <summary>Protocol-relative and backslash forms both resolve to another origin.</summary>
    private static bool EscapesToAnotherOrigin(string path) =>
        path.StartsWith("//", StringComparison.Ordinal) || path.StartsWith("/\\", StringComparison.Ordinal);

    private static bool HasQueryOrFragment(string path) =>
        path.Contains('?') || path.Contains('#');
}
