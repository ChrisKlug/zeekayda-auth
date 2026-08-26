using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupVerifier"/> that initializes whatever <see cref="ISigningKeyRing"/>
/// is registered, once per host startup — so a misconfigured signing key fails the host rather than
/// the first request — and then reconciles
/// <see cref="IdTokenOptions.AdvertisedSigningAlgorithms"/> against the key set it built.
/// </summary>
/// <remarks>
/// <para>
/// A silent no-op when no <see cref="ISigningKeyRing"/> is registered at all: <c>AddZeeKayDaSigningKeys()</c>
/// (the health check registration) deliberately never registers a ring, so a host that adds only the
/// health check must still start. A host that serves the protocol endpoints is held to the stronger
/// rule by <c>SigningKeyRingPresenceValidator</c> instead.
/// </para>
/// <para>
/// Registered from <c>AddZeeKayDaAuthCore()</c> as well as from
/// <see cref="Extensions.ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource{TSource}(IServiceCollection)"/>,
/// so the ring is initialized before <c>ClientRepositoryStartupActivator</c> validates client
/// registrations against the advertised set. <c>TryAddEnumerable</c> makes the pair idempotent, and
/// verifiers run in registration order, so the earlier registration wins the position.
/// </para>
/// </remarks>
internal sealed class SigningKeyRingStartupVerifier : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRing";

    /// <inheritdoc/>
    /// <remarks>
    /// Delegates to the internal <c>ISigningKeyRing.InitializeAsync</c> and lets any thrown
    /// <see cref="ZeeKayDaConfigurationException"/> propagate — the runner treats it as if its
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had already been added to
    /// <paramref name="context"/>.
    /// </remarks>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var ring = scopedServices.GetService<ISigningKeyRing>();
        if (ring is null)
            return;

        await ring.InitializeAsync(cancellationToken).ConfigureAwait(false);

        VerifyAdvertisedAlgorithms(context, scopedServices, ring);
    }

    /// <summary>
    /// Reconciles the operator's optional narrowing filter with the key set the ring just built, and
    /// checks the resulting advertised set against what OpenID Connect Discovery requires of it.
    /// Runs after <c>InitializeAsync</c>, which is what makes <see cref="ISigningKeyRing.Current"/>
    /// safe to read here.
    /// </summary>
    private static void VerifyAdvertisedAlgorithms(
        StartupVerificationContext context, IServiceProvider scopedServices, ISigningKeyRing ring)
    {
        var options = scopedServices.GetService<IOptions<AuthorizationServerOptions>>();
        var filter = options?.Value.IdToken.AdvertisedSigningAlgorithms;
        var keySet = ring.Current;

        if (filter is not null)
            VerifyFilter(context, keySet, filter);

        // Only for a host that serves a discovery document. A core-only host — one that called
        // AddZeeKayDaAuthCore() without AddZeeKayDaAuth(), so no AuthorizationServerOptions are
        // registered — publishes no metadata, and warning it about a Discovery §3 requirement it
        // is not subject to is noise.
        if (options is not null)
            VerifyRs256IsAdvertised(context, AdvertisedSigningAlgorithms.Resolve(keySet, filter));
    }

    /// <summary>
    /// The three ways a narrowing filter can disagree with the key set: excluding the signing key's
    /// own algorithm (fatal), withholding one a published key still uses (a warning about live
    /// tokens), and naming one no key uses at all (a warning about a no-op).
    /// </summary>
    private static void VerifyFilter(
        StartupVerificationContext context, SigningKeySet keySet, ICollection<SigningAlgorithm> filter)
    {
        var signingAlgorithm = keySet.SigningKey.Algorithm;

        if (!filter.Contains(signingAlgorithm))
        {
            context.AddFailure(
                "signing.advertised_algorithms.excludes_signing_key",
                $"IdToken.AdvertisedSigningAlgorithms is [{Format(filter)}], which excludes " +
                $"{signingAlgorithm} — the algorithm of the key that signs ('" +
                $"{keySet.SigningKey.SourceId.Value}'). The server would advertise no algorithm it " +
                $"actually issues tokens with. Add {signingAlgorithm} to the filter, or set " +
                "IdToken.AdvertisedSigningAlgorithms to null to advertise the whole published key set.");
        }

        // Withheld, but a published key still uses it: relying parties that pin acceptance to
        // discovery will reject tokens that key signed while they are still live and its kid is
        // still in the JWKS. The signing key's own algorithm is excluded — that case already
        // failed above, and reporting it twice would bury the fatal message.
        var withheld = keySet.AdvertisedAlgorithms
            .Where(algorithm => algorithm != signingAlgorithm && !filter.Contains(algorithm))
            .ToArray();

        if (withheld.Length > 0)
        {
            // Information, not Warning: every filter that narrows anything at all withholds a
            // published algorithm, so at Warning this would fire on every correct use of the
            // feature — and a warning that fires on correct use is one operators learn to ignore,
            // which costs exactly the case that matters. Distinguishing a retiring key (whose
            // tokens are live) from a staged one (which has never signed) needs slot identity that
            // SigningKeySet does not carry; until it does (#553), this records rather than alarms.
            context.AddWarning(
                "signing.advertised_algorithms.withholds_published_algorithm",
                "IdToken.AdvertisedSigningAlgorithms withholds {WithheldAlgorithms}, which the " +
                "published key set still uses. Those keys stay in the JWKS, so tokens they signed " +
                "remain verifiable, but a relying party that pins acceptance to " +
                "id_token_signing_alg_values_supported will reject them until they expire.",
                LogLevel.Information,
                Format(withheld));
        }

        var absent = filter
            .Where(algorithm => !keySet.AdvertisedAlgorithms.Contains(algorithm))
            .ToArray();

        if (absent.Length > 0)
        {
            // A no-op rather than a misstatement: the advertised set is an intersection, so an
            // algorithm with no key behind it is never advertised whatever the filter says.
            context.AddWarning(
                "signing.advertised_algorithms.absent_from_key_set",
                "IdToken.AdvertisedSigningAlgorithms names {AbsentAlgorithms}, which no configured " +
                "signing key uses; the published key set uses {PublishedAlgorithms}. Those entries " +
                "have no effect — discovery advertises only algorithms the server holds a key for.",
                Format(absent),
                Format(keySet.AdvertisedAlgorithms));
        }
    }

    /// <summary>
    /// OpenID Connect Discovery 1.0 §3 requires <c>RS256</c> in
    /// <c>id_token_signing_alg_values_supported</c>. Warns rather than injecting it: an algorithm
    /// with no key behind it is exactly what this issue's derivation exists to make
    /// unrepresentable, and a false advertisement is worse than a non-conformant honest one.
    /// </summary>
    private static void VerifyRs256IsAdvertised(
        StartupVerificationContext context, IReadOnlyList<SigningAlgorithm> advertised)
    {
        if (advertised.Contains(SigningAlgorithm.RS256))
            return;

        context.AddWarning(
            "signing.advertised_algorithms.rs256_absent",
            "id_token_signing_alg_values_supported will be {AdvertisedAlgorithms}, which omits " +
            "RS256. OpenID Connect Discovery 1.0 section 3 requires RS256 to be included, and a " +
            "relying party may assume it. Configure a key that signs RS256, or accept that clients " +
            "restricted to RS256 cannot use this server.",
            Format(advertised));
    }

    private static string Format(IEnumerable<SigningAlgorithm> algorithms) => string.Join(", ", algorithms);
}
