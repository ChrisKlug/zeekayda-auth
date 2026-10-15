using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Initializes the registered <see cref="SigningKeyRing"/> at startup, so a bad key fails the host rather
/// than a request, then warns about its algorithm and retention. A no-op when no ring is registered.
/// </summary>
internal sealed class SigningKeyRingActivator(
    IOptions<AuthorizationServerOptions> options,
    SigningKeyRing? ring = null) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRing";

    /// <inheritdoc/>
    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (ring is null)
            return;

        await ring.EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        VerifyRs256IsAdvertised(context, ring.Current.Algorithm);
        VerifyRetention(context);
    }

    /// <summary>Warns about a retention below the default, which shortens how long a failed handover can sign on.</summary>
    private void VerifyRetention(StartupVerificationContext context)
    {
        var configured = options.Value.SigningKeys.RetainRetiredKeysFor;
        var recommended = SigningKeyOptions.DefaultRetainRetiredKeysFor(options.Value);
        if (configured is not { } retention || retention >= recommended)
            return;

        context.AddWarning(
            "signing.retain_retired_keys_for.below_default",
            "SigningKeys.RetainRetiredKeysFor is {Configured}, below its default of {Default}. A retired key " +
            "drops from the key set sooner, so a replica whose handover to a new key is slow or fails has less " +
            "time before the tokens it signs stop verifying at other replicas.",
            retention,
            recommended);
    }

    /// <summary>
    /// Warns, rather than advertise falsely, when the server does not sign with the <c>RS256</c> that OpenID
    /// Connect Discovery 1.0 §3 requires.
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
