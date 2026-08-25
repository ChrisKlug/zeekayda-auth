namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Collects the filesystem paths one file-based signing configuration names, and reports whether any
/// two slots name the same file or a path the operating system cannot resolve.
/// </summary>
/// <remarks>
/// <para>
/// Shared by the PEM and PFX options validators, which need the identical rule: every path across
/// <c>Previous</c>, <c>Current</c> and <c>Next</c> must be distinct, because two slots sharing one
/// would publish a single key twice under two slot names, or make the same file both the outgoing and
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
internal sealed class SigningFilePathSet
{
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    /// <summary>Gets whether two tracked paths resolved to the same file.</summary>
    public bool HasDuplicate { get; private set; }

    /// <summary>Gets whether a tracked path could not be resolved by the operating system.</summary>
    public bool HasUnresolvable { get; private set; }

    /// <summary>
    /// Tracks one configured path. A <see langword="null"/>, empty, or whitespace-only path is
    /// ignored: the caller reports those under its own slot-specific message, and two independently
    /// empty values are not "the same path".
    /// </summary>
    public void Track(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException or IOException)
        {
            // An embedded NUL, a path over the platform limit, or — for a relative path, which
            // resolves against the current directory — an I/O failure reading that directory. All are
            // configuration errors like any other and belong in the aggregated result, not thrown out
            // of a validator where they would escape as something other than an options failure.
            // DirectoryNotFoundException derives from IOException, so a deleted working directory is
            // covered.
            HasUnresolvable = true;
            return;
        }

        if (!_seen.Add(fullPath))
            HasDuplicate = true;
    }

    /// <summary>
    /// Adds an aggregated error for each problem found, naming <paramref name="optionsTypeName"/> so
    /// the operator sees the type they configured.
    /// </summary>
    public void AppendErrors(string optionsTypeName, List<string> errors)
    {
        if (HasUnresolvable)
        {
            errors.Add(
                $"A {optionsTypeName} slot names a path the operating system cannot resolve — it " +
                "contains an invalid character (such as an embedded NUL) or exceeds the platform's " +
                "maximum path length.");
        }

        if (HasDuplicate)
        {
            errors.Add(
                $"Two {optionsTypeName} slots reference the same file. Every configured path must be " +
                "a distinct file.");
        }
    }
}
