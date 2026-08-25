namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// The shared path rule for a file-based signing configuration: every path it names must resolve, and
/// no two may resolve to the same file.
/// </summary>
/// <remarks>
/// <para>
/// Shared by the PEM and PFX options validators, which need the identical rule: two slots sharing a
/// file would publish one key twice under two slot names, or make the same file both the outgoing and
/// the incoming key of a rotation.
/// </para>
/// <para>
/// Each non-empty path is normalized via <see cref="Path.GetFullPath(string)"/> before comparison, so
/// differences like <c>tls.pfx</c> vs <c>./tls.pfx</c> are still caught. That call is pure string
/// canonicalization only for a rooted path; for a relative one it reads the current directory, which
/// is why I/O failures are caught and reported rather than thrown. Symlink resolution and
/// case-insensitive-filesystem comparison are deliberately out of scope: if two paths are equivalent
/// but not caught here, the result is a load failure or a duplicate-kid rejection in
/// <c>SigningKeySetBuilder</c>, not key confusion.
/// </para>
/// </remarks>
internal static class SigningFilePaths
{
    /// <summary>
    /// Appends an error for each problem found across <paramref name="paths"/>.
    /// </summary>
    /// <param name="optionsTypeName">The options type to name in the errors, as the operator configured it.</param>
    /// <param name="distinctnessRequirement">
    /// How the caller's own configuration spells the rule — PEM has a <c>KeyPath</c> beside its slot
    /// paths, PFX does not — so the error names the properties the operator actually set.
    /// </param>
    /// <param name="errors">The aggregated error list to append to.</param>
    /// <param name="paths">
    /// Every path the configuration names. A <see langword="null"/>, empty, or whitespace-only entry
    /// is ignored: the caller reports those under its own slot-specific message, and two
    /// independently empty values are not "the same path".
    /// </param>
    public static void AppendPathErrors(
        string optionsTypeName,
        string distinctnessRequirement,
        List<string> errors,
        params ReadOnlySpan<string?> paths)
    {
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
                // An embedded NUL, a path over the platform limit, or — for a relative path, which
                // resolves against the current directory — an I/O failure reading that directory. All
                // are configuration errors like any other and belong in the aggregated result, not
                // thrown out of a validator where they would escape as something other than an options
                // failure. DirectoryNotFoundException derives from IOException, so a deleted working
                // directory is covered.
                hasUnresolvable = true;
                continue;
            }

            if (!seen.Add(fullPath))
                hasDuplicate = true;
        }

        if (hasUnresolvable)
        {
            errors.Add(
                $"A {optionsTypeName} slot names a path the operating system cannot resolve — it " +
                "contains an invalid character (such as an embedded NUL) or exceeds the platform's " +
                "maximum path length.");
        }

        if (hasDuplicate)
            errors.Add($"Two {optionsTypeName} slots reference the same file. {distinctnessRequirement}");
    }
}
