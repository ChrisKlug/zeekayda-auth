namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// The host's source of subject claims. The framework asks it for a subject's claims every time a
/// grant becomes tokens, and never reads an identity store itself.
/// </summary>
/// <remarks>
/// <para>
/// Register an implementation with <c>AddClaimsProvider&lt;TProvider&gt;()</c>; a host without one
/// fails startup. The provider is resolved from the request scope, so it may take a per-request
/// database context.
/// </para>
/// <para>
/// The provider is called fresh on every issuance, including every refresh-token rotation, so a
/// subject whose claims changed or whose account was disabled is reflected at the next token
/// rather than at the end of an unbounded refresh chain. A provider that wants to spare its
/// identity store may cache on <see cref="ClaimsProviderContext.Sub"/> together with
/// <see cref="ClaimsProviderContext.FamilyId"/>, for a lifetime well under the shortest
/// access-token lifetime it serves; the family id alone is never a key, since it is absent at
/// userinfo.
/// </para>
/// <para>
/// What the provider returns is a pool. Which claims land in which token is decided afterwards
/// from the granted scopes and the client's registration, so returning more than
/// <see cref="ClaimsProviderContext.ClaimTypes"/> asks for is harmless, and returning less
/// simply omits those claims. Protocol claims such as <c>sub</c>, <c>iss</c> and <c>aud</c> are
/// written by the framework from the grant; a record with one of those names is discarded.
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
    ValueTask<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context,
        CancellationToken cancellationToken = default);
}
