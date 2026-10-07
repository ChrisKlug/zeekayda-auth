using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupActivator"/> that initializes whatever <see cref="SigningKeyRing"/>
/// is registered, once per host startup — so a misconfigured signing key fails the host rather than
/// the first request — and then checks the algorithm it signs under against OpenID Connect Discovery.
/// </summary>
/// <remarks>
/// <para>
/// A silent no-op when no <see cref="SigningKeyRing"/> is registered at all: <c>AddZeeKayDaSigningKeys()</c>
/// (the health check registration) deliberately never registers a ring, so a host that adds only the
/// health check must still start. A host that serves the protocol endpoints is held to the stronger
/// rule by <c>SigningKeyRingPresenceVerifier</c> instead.
/// </para>
/// <para>
/// An activator rather than a verifier because it calls into a caller-supplied
/// <see cref="ISigningKeySource"/> — source I/O and a real signing self-test, a remote call on the
/// Key Vault providers. Its phase does not run at all when a cheap configuration check has already
/// failed. Nothing depends on its position within that phase: a check needing the key set calls
/// <c>EnsureInitializedAsync</c> itself, which is idempotent.
/// </para>
/// </remarks>
internal sealed class SigningKeyRingActivator(SigningKeyRing? ring = null) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRing";

    /// <inheritdoc/>
    /// <remarks>
    /// Delegates to the internal <c>SigningKeyRing.EnsureInitializedAsync</c> and lets any thrown
    /// <see cref="ZeeKayDaConfigurationException"/> propagate — the runner treats it as if its
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had already been added to
    /// <paramref name="context"/>.
    /// </remarks>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (ring is null)
            return;

        await ring.EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        VerifyRs256IsAdvertised(context, ring.Current.Algorithm);
    }

    /// <summary>
    /// OpenID Connect Discovery 1.0 §3 requires <c>RS256</c> in
    /// <c>id_token_signing_alg_values_supported</c>. Warns rather than injecting it: discovery
    /// advertises only the algorithm the server signs with, and a false advertisement is worse than
    /// a non-conformant honest one.
    /// </summary>
    private static void VerifyRs256IsAdvertised(StartupVerificationContext context, SigningAlgorithm algorithm)
    {
        if (algorithm == SigningAlgorithm.RS256)
            return;

        context.AddWarning(
            "signing.advertised_algorithms.rs256_absent",
            "id_token_signing_alg_values_supported will be {AdvertisedAlgorithm}, which omits " +
            "RS256. OpenID Connect Discovery 1.0 section 3 requires RS256 to be included, and a " +
            "relying party may assume it. Use a signing source for RS256, or accept that clients " +
            "restricted to RS256 cannot use this server.",
            algorithm);
    }
}
