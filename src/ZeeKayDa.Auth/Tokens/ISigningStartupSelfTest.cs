namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Optional startup self-test surface for an <see cref="IJwtSigningService"/> implementation.
/// Deliberately a separate interface rather than a member on <see cref="IJwtSigningService"/> itself
/// — adding a member there would be a breaking change for any external, out-of-tree implementation
/// of that interface. A registered <see cref="IJwtSigningService"/> that does not implement this
/// interface simply does not receive the framework-owned startup self-test
/// (see <c>SigningStartupSelfTestHostedService</c>).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="JwtSigningService{TOptions}"/> implements this interface <b>explicitly</b> and does not
/// mark the implementation <see langword="virtual"/>, so no derived provider can override or weaken
/// it — the self-test is a base-class-owned invariant, not a per-provider extension point.
/// </para>
/// <para>
/// The sign-and-verify check itself is not unique to startup: it runs on every active-signer
/// handoff (initial materialization <em>and</em> every subsequent rotation) inside
/// <see cref="JwtSigningService{TOptions}"/>'s own handoff logic. This interface's
/// sole purpose is to let the framework force that first handoff to happen eagerly, at host
/// startup, rather than lazily on the first real token-issuing request.
/// </para>
/// </remarks>
public interface ISigningStartupSelfTest
{
    /// <summary>
    /// Forces materialization of the currently active signer (calling <c>CreateSignerAsync</c>
    /// exactly as <c>SignAsync</c> would), which — as a consequence of every signer handoff being
    /// self-tested — also proves that signer's signature verifies against that same key's own
    /// listed public key before this method returns.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the signature produced by the active signer does not verify against the public
    /// key listed for that same key — proof that the private key materialized for signing does not
    /// match the public key whose <c>kid</c> is being published.
    /// </exception>
    ValueTask VerifyActiveSignerAsync(CancellationToken cancellationToken = default);
}
