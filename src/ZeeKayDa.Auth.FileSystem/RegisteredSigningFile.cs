namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One certificate registered with a file-based signing provider (PEM or PFX).
/// </summary>
/// <remarks>
/// <see cref="Id"/> is the path used as this entry's identity — its rotation ordering, the
/// provider's <c>KeyId</c>, and diagnostics. <see cref="AdditionalPaths"/> lists other filesystem
/// paths backing this same entry without being a rotation entry of their own (currently only the
/// PEM provider's optional separate private-key file): they get the same permission hardening as
/// <see cref="Id"/>, but never participate in rotation ordering or diagnostics.
/// </remarks>
internal readonly record struct RegisteredSigningFile
{
    /// <summary>
    /// Initialises a registered file.
    /// </summary>
    /// <param name="id">The path used as this entry's identity — see this type's remarks.</param>
    /// <param name="additionalPaths">
    /// Any other paths backing this same entry (for example, a PEM provider's separately-registered
    /// private-key file). Defaults to none.
    /// </param>
    public RegisteredSigningFile(string id, IReadOnlyList<string>? additionalPaths = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        Id = id;
        AdditionalPaths = additionalPaths ?? [];
    }

    /// <summary>
    /// Gets the path used as this entry's identity — see this type's remarks.
    /// </summary>
    public string Id { get; }

    /// <summary>
    /// Gets any other paths backing this same entry, in addition to <see cref="Id"/> — see this
    /// type's remarks.
    /// </summary>
    public IReadOnlyList<string> AdditionalPaths { get; }

    /// <summary>
    /// Gets every filesystem path backing this entry — <see cref="Id"/> followed by
    /// <see cref="AdditionalPaths"/> — the full set that must be stat'd for mtime-change tracking.
    /// </summary>
    public IEnumerable<string> AllPaths => AdditionalPaths.Count == 0 ? [Id] : [Id, .. AdditionalPaths];
}
