namespace ZeeKayDa.Auth.Configuration;

/// <summary>Validates a host-relative interaction path at startup, so it can never become an open redirect.</summary>
internal static class InteractionPath
{
    /// <summary>The failure for <paramref name="path"/> when it is set and not <see cref="IsSafe"/>.</summary>
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? path, string optionPath, string code)
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

    /// <summary>Whether <paramref name="path"/> is an absolute local path a browser cannot resolve to another origin.</summary>
    public static bool IsSafe(string path)
    {
        if (!path.StartsWith('/'))
            return false;

        // Browsers strip tab/CR/LF, turning "/<tab>/evil.com" into "//evil.com".
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
