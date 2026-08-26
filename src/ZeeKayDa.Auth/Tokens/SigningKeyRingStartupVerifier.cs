using Microsoft.Extensions.DependencyInjection;
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

        VerifyAdvertisedAlgorithmFilter(context, scopedServices, ring);
    }

    /// <summary>
    /// Reconciles the operator's optional narrowing filter with the key set the ring just built.
    /// Runs after <c>InitializeAsync</c>, which is what makes <see cref="ISigningKeyRing.Current"/>
    /// safe to read here.
    /// </summary>
    private static void VerifyAdvertisedAlgorithmFilter(
        StartupVerificationContext context, IServiceProvider scopedServices, ISigningKeyRing ring)
    {
        var options = scopedServices.GetService<IOptions<AuthorizationServerOptions>>();
        var filter = options?.Value.IdToken.AdvertisedSigningAlgorithms;

        // No filter advertises the whole published set, which is derived and therefore always
        // consistent with the keys — there is nothing to reconcile.
        if (filter is null)
            return;

        var keySet = ring.Current;

        if (!filter.Contains(keySet.SigningKey.Algorithm))
        {
            context.AddFailure(
                "signing.advertised_algorithms.excludes_signing_key",
                $"IdToken.AdvertisedSigningAlgorithms is [{Format(filter)}], which excludes " +
                $"{keySet.SigningKey.Algorithm} — the algorithm of the key that signs ('" +
                $"{keySet.SigningKey.SourceId.Value}'). The server would advertise no algorithm it " +
                $"actually issues tokens with. Add {keySet.SigningKey.Algorithm} to the filter, or " +
                "set IdToken.AdvertisedSigningAlgorithms to null to advertise the whole published " +
                "key set.");
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

    private static string Format(IEnumerable<SigningAlgorithm> algorithms) => string.Join(", ", algorithms);
}
