using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupVerifier"/> that cross-checks
/// <see cref="AuthorizationServerOptions.IdToken"/>'s statically-configured
/// <see cref="IdTokenOptions.SigningAlgValuesSupported"/> — the list advertised in the discovery
/// document as <c>id_token_signing_alg_values_supported</c> — against the algorithms the
/// registered <see cref="IJwtSigningService"/> actually holds keys for. Registered once by
/// <c>ZeeKayDaAuthCoreServiceCollectionExtensions.AddZeeKayDaAuthCore</c>.
/// </summary>
/// <remarks>
/// <para>
/// The check is one-directional. An advertised algorithm with no corresponding key is a startup
/// failure: there is no runtime backstop today, so a server that advertises an algorithm it cannot
/// actually produce would silently mislead relying parties until a token in that algorithm was
/// requested. The reverse is not checked and must not be: a signing provider legitimately holds
/// keys for an algorithm that is no longer advertised during a migration or retirement window — for
/// example, an old key kept only so already-issued tokens (or other verifiers) can still validate
/// against it — and flagging that as an error would break that supported workflow.
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
    /// expected shape for a host that has not (yet) configured any signing provider.
    /// </remarks>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var signingService = scopedServices.GetService<IJwtSigningService>();
        if (signingService is null)
            return;

        var advertised = options.Value.IdToken.SigningAlgValuesSupported;
        var keys = await signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
        var producible = keys.Select(k => k.Algorithm).ToHashSet();

        var unavailable = advertised.Distinct().Where(a => !producible.Contains(a)).ToArray();
        if (unavailable.Length == 0)
            return;

        var producibleDescription = producible.Count == 0
            ? "no algorithms at all"
            : $"[{string.Join(", ", producible)}]";

        context.AddFailure(
            "signing.advertised_algorithm_unavailable",
            $"IdToken.SigningAlgValuesSupported advertises [{string.Join(", ", unavailable)}], " +
            $"but the registered signing provider holds no key for it. The provider's current keys " +
            $"cover {producibleDescription}.");
    }

    /// <inheritdoc/>
    public string Name => "AdvertisedSigningAlgorithms";
}
