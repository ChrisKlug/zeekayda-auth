namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What one <see cref="ISigningKeySource.ReadAsync"/> found: the keys it could list, and the entries
/// it could not.
/// </summary>
/// <param name="Keys">Every key the source could list, in any order.</param>
/// <param name="Failures">
/// Every entry the source holds but could not list, each with its own failure. Such an entry is
/// neither published nor ever signs, and the health check reports it; the keys around it carry on.
/// </param>
/// <remarks>
/// A failure that is about one entry — a key file too permissive, a certificate without a private
/// key — is reported here, never thrown, so it cannot hold up the rest of the listing: deleting one
/// key while another is broken still unlists the deleted key. A failure that is not about one entry
/// — a store that cannot be opened, a vault that cannot be reached — throws from
/// <see cref="ISigningKeySource.ReadAsync"/>, and the framework keeps the keys it last read.
/// </remarks>
public sealed record SourceKeyListing(IReadOnlyList<SourceKey> Keys, IReadOnlyList<SourceKeyFailure> Failures);
