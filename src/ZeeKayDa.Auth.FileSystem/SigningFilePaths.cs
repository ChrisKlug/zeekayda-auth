namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// The PEM and PFX validators' shared path rule: every path must resolve, and no two may resolve to the
/// same file, which would list one key twice under two source ids.
/// </summary>
/// <remarks>
/// Paths are compared after <see cref="Path.GetFullPath(string)"/>. Symlinks and case-insensitive
/// filesystems are not resolved; a duplicate missed that way lists one key twice, which the ring builds into one key.
/// </remarks>
internal static class SigningFilePaths
{
    /// <summary>
    /// Returns a failure for each problem found across <paramref name="paths"/>.
    /// </summary>
    /// <param name="optionsTypeName">The options type to name in the failures, as the operator configured it.</param>
    /// <param name="codePrefix">The code prefix the caller's path failures carry.</param>
    /// <param name="distinctnessRequirement">
    /// How the caller's own configuration spells the rule — PEM has a <c>KeyPath</c> beside each
    /// path, PFX does not — so the error names the properties the operator actually set.
    /// </param>
    /// <param name="paths">
    /// Every path the configuration names. A <see langword="null"/>, empty, or whitespace-only entry
    /// is ignored: the caller reports those under its own per-entry message, and two
    /// independently empty values are not "the same path".
    /// </param>
    public static List<ZeeKayDaConfigurationFailure> PathFailures(
        string optionsTypeName,
        string codePrefix,
        string distinctnessRequirement,
        params ReadOnlySpan<string?> paths)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var hasDuplicate = false;
        var hasUnresolvable = false;

        foreach (var path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
                continue;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException)
            {
                // A relative path reads the current directory, so this includes I/O failures; a validator reports, never throws.
                hasUnresolvable = true;
                continue;
            }

            if (!seen.Add(fullPath))
                hasDuplicate = true;
        }

        if (hasUnresolvable)
        {
            failures.Add(new(
                $"{codePrefix}.unresolvable",
                $"A {optionsTypeName} entry names a path the operating system cannot resolve — it " +
                "contains an invalid character (such as an embedded NUL) or exceeds the platform's " +
                "maximum path length."));
        }

        if (hasDuplicate)
        {
            failures.Add(new(
                $"{codePrefix}.duplicate",
                $"Two {optionsTypeName} entries reference the same file. {distinctnessRequirement}"));
        }

        return failures;
    }
}
