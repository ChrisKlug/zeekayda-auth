using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more X.509 certificates from a Windows
/// Certificate Store by thumbprint and signs locally, in process, using each certificate's CNG/CAPI
/// private-key handle.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LoadKeysAsync"/> derives the currently trusted certificate set from the certificates'
/// own <c>NotBefore</c>/<c>NotAfter</c> fields via <see cref="WindowsCertificateStoreSigningKeyRotation"/> —
/// see that type's remarks for the full rationale (why the anchor differs from the Key Vault
/// providers' <c>CreatedOn</c>-based derivation). Only the active certificate's private key is ever
/// held: every other included certificate (published-but-not-yet-active, or still within its
/// retirement window) gets only a public-only handle, since it is never used to sign — only exposed
/// via the JWKS (ADR 0011 §3.3(c)).
/// </para>
/// <para>
/// This class does not override <see cref="JwtSigningService{TOptions}.SignInputAsync"/> — per ADR
/// 0011 Amendment 2(a), this provider signs with local key handles exactly like the development
/// provider and the Azure Key Vault *cached* signing provider, so the base class's default
/// local-crypto implementation is exactly what it needs. There is also no
/// <c>WindowsCertificateStoreSigningException</c> transport type: unlike Key Vault, there is no
/// network round trip at sign time, so there is no transient-fault surface to wrap.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint of each certificate's public key (via
/// <see cref="WindowsCertificateSigningKeyDescriptorFactory"/>), never the certificate's own X.509
/// thumbprint — a <c>kid</c> is always public, so using the store thumbprint directly would be
/// exactly the kind of external-identifier leak <see cref="JwkThumbprint"/> exists to avoid.
/// </para>
/// </remarks>
internal sealed class WindowsCertificateStoreSigningJwtSigningService : JwtSigningService<WindowsCertificateStoreSigningOptions>
{
    private readonly IOptions<WindowsCertificateStoreSigningOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ICertificateStoreReader _storeReader;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService> _logger;

    public WindowsCertificateStoreSigningJwtSigningService(
        IOptions<WindowsCertificateStoreSigningOptions> options,
        TimeProvider timeProvider,
        ICertificateStoreReader storeReader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<WindowsCertificateStoreSigningJwtSigningService> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(storeReader);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _storeReader = storeReader;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var thumbprints = new List<string>(1 + options.AdditionalThumbprints.Count) { options.Thumbprint };
        thumbprints.AddRange(options.AdditionalThumbprints);

        // Fetch every registered certificate up front — the timeline needs every registered
        // certificate's NotBefore/NotAfter, not just the ones that end up "included", to correctly
        // compute retirement anchors.
        var certificatesByThumbprint = new Dictionary<string, X509Certificate2>(thumbprints.Count, StringComparer.Ordinal);
        try
        {
            foreach (var thumbprint in thumbprints)
                certificatesByThumbprint[thumbprint] = _storeReader.GetCertificate(thumbprint, options.StoreLocation, options.StoreName);

            var now = _timeProvider.GetUtcNow();
            var infos = certificatesByThumbprint
                .Select(kvp => new WindowsCertificateStoreSigningKeyRotation.RegisteredCertificateInfo(
                    kvp.Key, new DateTimeOffset(kvp.Value.NotBefore), new DateTimeOffset(kvp.Value.NotAfter)))
                .ToList();

            var timeline = WindowsCertificateStoreSigningKeyRotation.BuildActivationTimeline(infos);
            var active = WindowsCertificateStoreSigningKeyRotation.SelectActiveVersion(timeline, now)
                ?? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.windows_certificate_store.no_active_certificate",
                    "No registered certificate is currently eligible to sign. Verify at least one " +
                    "registered certificate's NotBefore has arrived and its NotAfter has not yet passed."));

            var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
            var included = WindowsCertificateStoreSigningKeyRotation.SelectIncludedCertificates(timeline, active, now, retirementWindow);

            LogCertificateStatuses(timeline, active, included, now, options.RefreshInterval, retirementWindow, certificatesByThumbprint);
            WarnIfActiveCertificateExpiringSoon(active, now);

            var keyPairs = new List<SigningKeyPair>(included.Count);
            try
            {
                foreach (var entry in included)
                {
                    var thumbprint = entry.Certificate.Thumbprint;
                    var certificate = certificatesByThumbprint[thumbprint];
                    var isActive = string.Equals(thumbprint, active.Certificate.Thumbprint, StringComparison.Ordinal);

                    var (publicKey, keyType) = WindowsCertificateKeyExtractor.ExtractPublicKey(certificate, thumbprint);
                    SigningKeyDescriptor descriptor;
                    try
                    {
                        descriptor = WindowsCertificateSigningKeyDescriptorFactory.BuildDescriptor(publicKey, keyType, options.Algorithm, thumbprint);
                    }
                    catch
                    {
                        // The key handle just obtained above was never added to keyPairs, so the
                        // outer catch below would not dispose it — do so here before rethrowing.
                        publicKey.Dispose();
                        throw;
                    }

                    AsymmetricAlgorithm signingKey;
                    if (isActive)
                    {
                        try
                        {
                            (signingKey, _) = WindowsCertificateKeyExtractor.ExtractPrivateKey(certificate, thumbprint);
                        }
                        catch
                        {
                            publicKey.Dispose();
                            throw;
                        }

                        // The public-only handle is now redundant: the private key just extracted
                        // carries the same public component.
                        publicKey.Dispose();
                    }
                    else
                    {
                        signingKey = publicKey;
                    }

                    keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = signingKey });
                }
            }
            catch
            {
                // Key material for any certificate already processed before the failure would
                // otherwise leak live handles.
                foreach (var pair in keyPairs)
                    pair.PrivateKey.Dispose();
                throw;
            }

            return new ValueTask<SigningKeySet>(new SigningKeySet(keyPairs));
        }
        finally
        {
            // GetRSAPrivateKey()/GetECDsaPrivateKey()/GetRSAPublicKey()/GetECDsaPublicKey() return
            // handle objects that remain valid after the parent X509Certificate2 is disposed
            // (CNG/CAPI key handle duplication, .NET Core 3.0+) — safe to dispose every fetched
            // certificate here, after all needed handles have already been extracted above.
            foreach (var certificate in certificatesByThumbprint.Values)
                certificate.Dispose();
        }
    }

    private void LogCertificateStatuses(
        IReadOnlyList<WindowsCertificateStoreSigningKeyRotation.ActivationEntry> timeline,
        WindowsCertificateStoreSigningKeyRotation.ActivationEntry active,
        IReadOnlyList<WindowsCertificateStoreSigningKeyRotation.ActivationEntry> included,
        DateTimeOffset now, TimeSpan refreshInterval, TimeSpan retirementWindow,
        IReadOnlyDictionary<string, X509Certificate2> certificatesByThumbprint)
    {
        // Unlike a purely static config fact (thumbprint/subject/expiry never change once a
        // certificate is loaded), each certificate's active/included/excluded status is a function
        // of `now` and genuinely changes over the lifetime of a long-running process as a rotation
        // progresses — so, unlike a one-shot log, this is re-evaluated and logged on every
        // LoadKeysAsync call (at most once per RefreshInterval) rather than only at first load.
        // Logging every registered certificate on every cycle — not just the currently-included
        // ones — is deliberate: it lets an operator see exactly what the current configuration
        // resolves to, including a certificate that is configured but has fallen out of the trusted
        // set entirely (its retirement window has elapsed) and can now safely be removed.
        var includedThumbprints = new HashSet<string>(
            included.Select(e => e.Certificate.Thumbprint), StringComparer.Ordinal);

        foreach (var entry in timeline)
        {
            var certificate = certificatesByThumbprint[entry.Certificate.Thumbprint];
            var status = DescribeStatus(entry, active, includedThumbprints, now, retirementWindow);

            _logger.LogInformation(
                "ZeeKayDa.Auth: Windows Certificate Store signing certificate '{Thumbprint}' " +
                "(subject '{Subject}', expires {NotAfter:O}) is {Status}.",
                entry.Certificate.Thumbprint, certificate.Subject, entry.Certificate.NotAfter, status);
        }

        if (WindowsCertificateStoreSigningKeyRotation.HasTooSoonPendingActivation(timeline, active, now, refreshInterval, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: certificate '{Thumbprint}' activates at {ActivatesAt:O}, which is less " +
                "than RefreshInterval ({RefreshInterval}) away from now. A relying party polling the " +
                "JWKS at RefreshInterval cadence may not have observed this certificate's public key " +
                "before it starts signing. Set this certificate's NotBefore at least RefreshInterval in " +
                "the future next time (see ADR 0011 §3.5 / issue #282).",
                soonestPending!.Value.Certificate.Thumbprint, soonestPending.Value.ActivatesAt, refreshInterval);
        }
    }

    private static string DescribeStatus(
        WindowsCertificateStoreSigningKeyRotation.ActivationEntry entry,
        WindowsCertificateStoreSigningKeyRotation.ActivationEntry active,
        HashSet<string> includedThumbprints, DateTimeOffset now, TimeSpan retirementWindow)
    {
        if (string.Equals(entry.Certificate.Thumbprint, active.Certificate.Thumbprint, StringComparison.Ordinal))
            return "the active signer";

        if (!includedThumbprints.Contains(entry.Certificate.Thumbprint))
        {
            return "NOT included in the JWKS - its retirement window has fully elapsed; safe to remove " +
                "from configuration";
        }

        if (entry.ActivatesAt > now)
            return $"included in the JWKS, not yet active (activates at {entry.ActivatesAt:O})";

        return "included in the JWKS, retired but still within its retirement window (until " +
            $"{entry.RetiredAt!.Value + retirementWindow:O})";
    }

    private void WarnIfActiveCertificateExpiringSoon(
        WindowsCertificateStoreSigningKeyRotation.ActivationEntry active, DateTimeOffset now)
    {
        // Re-evaluated on every LoadKeysAsync call, exactly like LogCertificateStatuses above:
        // whether the active certificate is within 30 days of expiry is genuinely time-varying — a
        // long-running process can cross into that window mid-lifetime. Repeats at most once per
        // RefreshInterval for as long as the condition holds.
        if (active.Certificate.NotAfter - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the active Windows Certificate Store signing certificate '{Thumbprint}' " +
                "expires at {NotAfter:O}, within 30 days. Rotate in a new certificate (via AddCertificate) " +
                "before it expires.",
                active.Certificate.Thumbprint, active.Certificate.NotAfter);
        }
    }
}
