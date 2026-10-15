namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The host's source of subject claims. The framework asks it for a subject's claims every time a
/// grant becomes tokens, and never reads an identity store itself.
/// </summary>
/// <remarks>
/// <para>
/// Register with <c>AddClaimsProvider&lt;TProvider&gt;()</c>; a host without one fails startup. Resolved
/// from the request scope, so it may take a per-request database context.
/// </para>
/// <para>
/// Called on every issuance, every refresh rotation included, so changed claims or a disabled account show
/// at the next token. A cache keys on <see cref="ClaimsProviderContext.Sub"/> with
/// <see cref="ClaimsProviderContext.FamilyId"/>, for well under the shortest access-token lifetime.
/// </para>
/// <para>
/// The result is a pool: selection afterwards decides which claims land where, so extra claims are
/// harmless and missing ones are omitted. A record named like a protocol claim (<c>sub</c>, <c>iss</c>,
/// <c>aud</c>) is discarded.
/// </para>
/// </remarks>
public interface IClaimsProvider
{
    /// <summary>
    /// Resolves the claims of the subject named by <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The subject, the granted scopes, the claim types that will be kept, and the grant family.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// <see cref="ClaimsResolutionResult.Resolved"/> with the subject's claims, or
    /// <see cref="ClaimsResolutionResult.SubjectInvalid"/> when the subject must not receive
    /// tokens. An exception is treated as an infrastructure failure: nothing is issued and the
    /// client is answered <c>server_error</c>.
    /// </returns>
    Task<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context,
        CancellationToken cancellationToken = default);
}
