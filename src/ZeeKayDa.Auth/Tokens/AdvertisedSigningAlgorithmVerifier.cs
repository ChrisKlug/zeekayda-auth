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
/// The check runs in both directions, asserting full equality between what is advertised and what
/// is producible. An advertised algorithm with no key able to sign a new token now or soon is a
/// startup failure: there is no runtime backstop today, so a server that advertises an algorithm it
/// cannot actually produce would silently mislead relying parties until a token in that algorithm
/// was requested. Conversely, every algorithm the provider can currently or soon produce — the
/// active key's algorithm, and the algorithm of every staged (not-yet-active) key — must itself be
/// advertised. This closes a deferred-migration gap: an operator who stages a new key before
/// updating the advertised list would otherwise pass startup today and have that key silently start
/// signing an unadvertised algorithm tomorrow, with no runtime re-check ever, since startup
/// verification is one-shot. Neither direction is checked against a key retained only for its
/// retirement window (kept so already-issued tokens, or other verifiers, can still validate against
/// it) — that is normal migration state, not a misconfiguration.
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
        CheckProducibleAlgorithmsAreAdvertised(context, advertised, snapshot);
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
        var unavailable = advertised.Distinct().Where(a => !snapshot.CanProduce(a)).ToArray();
        if (unavailable.Length == 0)
            return;

        // Always at least [ActiveAlgorithm] — a snapshot's producible set can never be empty.
        var producible = string.Join(", ", ProducibleAlgorithms(snapshot));

        context.AddFailure(
            "signing.advertised_algorithm_unavailable",
            $"IdToken.SigningAlgValuesSupported advertises [{string.Join(", ", unavailable)}], " +
            "but the registered signing provider holds no key able to sign a new token with it " +
            $"now or soon. The provider's currently producible algorithms cover [{producible}].");
    }

    /// <summary>
    /// Fails when an algorithm the provider can currently or soon produce — the active key's
    /// algorithm, or a staged (not-yet-active) key's algorithm — is not itself advertised. Reported
    /// as a single failure naming which of the unadvertised algorithms is active versus staged, so
    /// an operator can distinguish "your active signer isn't advertised" from "you staged a new
    /// algorithm without advertising it first".
    /// </summary>
    private static void CheckProducibleAlgorithmsAreAdvertised(
        StartupVerificationContext context,
        ICollection<SigningAlgorithm> advertised,
        SigningKeyProducibilitySnapshot snapshot)
    {
        var unadvertised = new List<string>();

        if (!advertised.Contains(snapshot.ActiveAlgorithm))
            unadvertised.Add($"{snapshot.ActiveAlgorithm} (active)");

        unadvertised.AddRange(snapshot.StagedAlgorithms
            .Where(a => !advertised.Contains(a))
            .Select(a => $"{a} (staged)"));

        if (unadvertised.Count == 0)
            return;

        context.AddFailure(
            "signing.producible_algorithm_not_advertised",
            $"The registered signing provider can sign a new token now or soon with " +
            $"[{string.Join(", ", unadvertised)}], but IdToken.SigningAlgValuesSupported does not " +
            $"advertise it (advertises [{string.Join(", ", advertised)}]). Every algorithm the " +
            "provider can currently or soon produce — active or staged — must be advertised in the " +
            "discovery document.");
    }

    private static IEnumerable<SigningAlgorithm> ProducibleAlgorithms(SigningKeyProducibilitySnapshot snapshot) =>
        new[] { snapshot.ActiveAlgorithm }.Concat(snapshot.StagedAlgorithms);
}
