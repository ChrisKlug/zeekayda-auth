namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// One certificate registered with a file-based signing provider (PEM or PFX).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Id"/> is the path used as this entry's <c>RotationKey.Id</c> — it determines the
/// entry's position in the rotation timeline, is passed to
/// <c>FileSigningJwtSigningService{TOptions}.LoadCertificateAsync</c>, and appears in diagnostics.
/// For the PFX provider, and for a PEM provider's combined cert+key file, <see cref="Id"/> is the
/// entry's only backing file.
/// </para>
/// <para>
/// <see cref="AdditionalPaths"/> lists any other filesystem paths that back this same entry without
/// being a rotation entry of their own — currently only the PEM provider's optional
/// separately-registered private-key file (issue #405). A path listed here must receive the same
/// mtime-change tracking and permission hardening as <see cref="Id"/> (so that either file changing
/// is treated as this entry changing), but never participates in <c>kid</c> derivation, rotation
/// ordering, or diagnostics keyed by entry identity — only <see cref="Id"/> does.
/// </para>
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
