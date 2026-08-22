using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupVerifier"/> that cross-checks
/// <see cref="AuthorizationServerOptions.IdToken"/>'s statically-configured
/// <see cref="IdTokenOptions.SigningAlgValuesSupported"/> — the list advertised in the discovery
/// document as <c>id_token_signing_alg_values_supported</c> — against the algorithms the
/// registered <see cref="IJwtSigningService"/> can actually sign a new token with. Registered once
/// by <c>ZeeKayDaAuthCoreServiceCollectionExtensions.AddZeeKayDaAuthCore</c>.
/// </summary>
/// <remarks>
/// <para>
/// The check runs in both directions. An advertised algorithm with no key able to sign a new token
/// now or soon is a startup failure: there is no runtime backstop today, so a server that
/// advertises an algorithm it cannot actually produce would silently mislead relying parties until
/// a token in that algorithm was requested. Conversely, the active signing key's algorithm must
/// itself be advertised — a server that signs with an algorithm it does not list is equally
/// misleading relying parties, just from the other direction. Neither direction is checked against
/// a key retained only for its retirement window (kept so already-issued tokens, or other
/// verifiers, can still validate against it) — that is normal migration state, not a
/// misconfiguration.
/// </para>
/// <para>
/// Resolves <see cref="IJwtSigningService"/> lazily from <c>scopedServices</c> at
/// <see cref="VerifyAsync"/> time, rather than taking it as a constructor dependency, mirroring
/// <see cref="SigningStartupSelfTestVerifier"/>: <c>AddZeeKayDaAuthCore()</c> is also called by
/// hosts that never register a signing key provider at all, and this verifier's registration must
/// stay harmless for them.
/// </para>
/// </remarks>
internal sealed class AdvertisedSigningAlgorithmVerifier(IOptions<AuthorizationServerOptions> options) : IStartupVerifier
{
    /// <inheritdoc/>
    /// <remarks>
    /// A silent no-op when no <see cref="IJwtSigningService"/> is registered at all — that is the
    /// expected shape for a host that has not (yet) configured any signing provider. When an
    /// <see cref="IJwtSigningService"/> <em>is</em> registered but does not implement
    /// <see cref="ISigningKeyProducibility"/> — for example, an external, out-of-tree
    /// implementation written before this interface existed — this records a warning naming the
    /// concrete resolved type and skips the check, rather than silently doing nothing. Every
    /// provider shipped in this repository implements <see cref="ISigningKeyProducibility"/> via
    /// <see cref="JwtSigningService{TOptions}"/>.
    /// </remarks>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var signingService = scopedServices.GetService<IJwtSigningService>();
        if (signingService is null)
            return;

        if (signingService is not ISigningKeyProducibility producibility)
        {
            context.AddWarning(
                "signing.advertised_algorithm_check_skipped",
                "ZeeKayDa.Auth: the registered IJwtSigningService ({Type}) does not implement " +
                "ISigningKeyProducibility; the advertised-signing-algorithm startup check was skipped.",
                signingService.GetType());
            return;
        }

        var advertised = options.Value.IdToken.SigningAlgValuesSupported;
        var snapshot = await producibility.GetProducibilityAsync(cancellationToken).ConfigureAwait(false);

        CheckAdvertisedAlgorithmsAreProducible(context, advertised, snapshot);
        CheckActiveAlgorithmIsAdvertised(context, advertised, snapshot);
    }

    /// <inheritdoc/>
    public string Name => "AdvertisedSigningAlgorithms";

    /// <summary>
    /// Fails when an advertised algorithm has no key able to sign a new token with it now or soon.
    /// </summary>
    private static void CheckAdvertisedAlgorithmsAreProducible(
        StartupVerificationContext context,
        ICollection<SigningAlgorithm> advertised,
        SigningKeyProducibilitySnapshot snapshot)
    {
        var unavailable = advertised.Distinct().Where(a => !snapshot.Algorithms.Contains(a)).ToArray();
        if (unavailable.Length == 0)
            return;

        var producibleDescription = snapshot.Algorithms.Count == 0
            ? "no algorithms at all"
            : $"[{string.Join(", ", snapshot.Algorithms)}]";

        context.AddFailure(
            "signing.advertised_algorithm_unavailable",
            $"IdToken.SigningAlgValuesSupported advertises [{string.Join(", ", unavailable)}], " +
            "but the registered signing provider holds no key able to sign a new token with it " +
            $"now or soon. The provider's currently producible algorithms cover {producibleDescription}.");
    }

    /// <summary>
    /// Fails when the active signing key's algorithm is not itself advertised — the server is
    /// signing new tokens with an algorithm the discovery document does not list.
    /// </summary>
    private static void CheckActiveAlgorithmIsAdvertised(
        StartupVerificationContext context,
        ICollection<SigningAlgorithm> advertised,
        SigningKeyProducibilitySnapshot snapshot)
    {
        if (advertised.Contains(snapshot.ActiveAlgorithm))
            return;

        context.AddFailure(
            "signing.active_algorithm_not_advertised",
            $"The registered signing provider's active signing key signs with " +
            $"{snapshot.ActiveAlgorithm}, but IdToken.SigningAlgValuesSupported does not advertise " +
            $"it (advertises [{string.Join(", ", advertised)}]). Tokens issued right now are signed " +
            "under an algorithm the discovery document does not list.");
    }
}
