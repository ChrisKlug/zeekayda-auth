using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// <see cref="IJwtSigningService"/> that loads one or more items from the macOS Keychain by label and
/// signs locally, in process, via a native <c>SecKeyRef</c> handle (see <see cref="Interop.SecKeyBackedRsa"/>/
/// <see cref="Interop.SecKeyBackedECDsa"/>).
/// </summary>
/// <remarks>
/// <para>
/// Each registered label (see <see cref="MacOsKeychainSigningOptions"/>) is either certificate-backed
/// or a bare, certificate-less key, auto-detected at load time: a certificate anchors on its own
/// <c>NotBefore</c>/<c>NotAfter</c>, exactly like the Windows Certificate Store provider; a bare key
/// uses an explicit <c>activatesAt</c>/<c>expiresAt</c> given via
/// <see cref="MacOsKeychainSigningOptions.AddKey(string, DateTimeOffset, DateTimeOffset?)"/>, or — if
/// it ends up being the <em>sole</em> registered key — no explicit activation at all (the single-key
/// bootstrap exemption). Both shapes are mapped onto the shared, anchor-agnostic
/// <see cref="RotationKey"/>/<see cref="SigningKeyRotation"/> core — see that type's remarks, and ADR
/// 0011 Amendment 6, for the full rationale.
/// </para>
/// <para>
/// This class does not override <see cref="JwtSigningService{TOptions}.SignInputAsync"/> — per ADR
/// 0011 Amendment 2(a), this provider signs with local key handles exactly like the Windows
/// Certificate Store provider, so the base class's default local-crypto implementation is exactly
/// what it needs. There is no network round trip at sign time, so there is no transient-fault
/// transport exception analogous to <c>AzureKeyVaultSigningException</c>.
/// </para>
/// <para>
/// Unlike the Windows provider, every registered item's signing key object
/// (<see cref="Interop.SecKeyBackedRsa"/>/<see cref="Interop.SecKeyBackedECDsa"/>) is already capable
/// of both roles — real signing <em>and</em> public-only export — without needing a second,
/// separately-extracted handle. To minimize how many live, signing-capable native handles are held at
/// once (narrowing the attack surface, even though no raw key bytes are ever exposed either way), only
/// the active key keeps its real signing handle; every other included item's public parameters are
/// captured into a plain, non-signing-capable <see cref="RSA"/>/<see cref="ECDsa"/> and its native
/// handle is released immediately.
/// </para>
/// <para>
/// <c>kid</c> is the RFC 7638 JWK thumbprint via the shared <see cref="SigningKeyDescriptorFactory"/>,
/// never a Keychain-native identifier.
/// </para>
/// </remarks>
internal sealed class MacOsKeychainSigningJwtSigningService : JwtSigningService<MacOsKeychainSigningOptions>
{
    private readonly IOptions<MacOsKeychainSigningOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly IKeychainItemReader _reader;
    private readonly ISigningKeyRetirementWindowProvider _retirementWindowProvider;
    private readonly ISanitizingLogger<MacOsKeychainSigningJwtSigningService> _logger;

    public MacOsKeychainSigningJwtSigningService(
        IOptions<MacOsKeychainSigningOptions> options,
        TimeProvider timeProvider,
        IKeychainItemReader reader,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<MacOsKeychainSigningJwtSigningService> logger)
        : base(options, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(retirementWindowProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _timeProvider = timeProvider;
        _reader = reader;
        _retirementWindowProvider = retirementWindowProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var options = _options.Value;
        var registrations = new List<RegisteredKeyLabel>(1 + options.AdditionalKeys.Count)
        {
            new(options.Label, ActivatesAt: null, ExpiresAt: null),
        };
        registrations.AddRange(options.AdditionalKeys);

        var itemsByLabel = new Dictionary<string, ResolvedKeychainItem>(registrations.Count, StringComparer.Ordinal);
        string? activeLabel = null;
        var returnedSuccessfully = false;
        try
        {
            foreach (var registration in registrations)
                itemsByLabel[registration.Label] = ResolveItem(registration, registrations.Count);

            var now = _timeProvider.GetUtcNow();
            var rotationKeys = itemsByLabel
                .Select(kvp => new RotationKey(kvp.Key, kvp.Value.ActivatesAt, kvp.Value.ExpiresAt))
                .ToList();

            var timeline = SigningKeyRotation.BuildActivationTimeline(rotationKeys);
            var active = SigningKeyRotation.SelectActiveKey(timeline, now)
                ?? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                    "signing.macos_keychain.no_active_key",
                    "No registered Keychain item is currently eligible to sign. Verify at least one " +
                    "registered item's activation time has arrived and its expiry has not yet passed."));
            activeLabel = active.Key.Id;

            var retirementWindow = _retirementWindowProvider.GetRetirementWindow();
            var included = SigningKeyRotation.SelectIncludedKeys(timeline, active, now, retirementWindow);

            LogKeyStatuses(timeline, active, included, now, options.RefreshInterval, retirementWindow, itemsByLabel);
            WarnIfActiveKeyExpiringSoon(active, now);

            var keyPairs = BuildKeyPairs(included, active, itemsByLabel, options.Algorithm);
            var result = new SigningKeySet(keyPairs);
            returnedSuccessfully = true;
            return new ValueTask<SigningKeySet>(result);
        }
        finally
        {
            // On success, every resolved item's native handle is either the returned SigningKeySet's
            // active key (kept alive, owned by the caller from here on) or has already had its public
            // parameters captured into a plain descriptor/public-only key by BuildKeyPairs — in both
            // cases, this reader-owned handle is now redundant here. This also covers items that never
            // made it into `included` at all (their retirement window fully elapsed). On failure, the
            // active label's own handle must also be released here (it is only exempted on success) —
            // SafeHandle/AsymmetricAlgorithm.Dispose() are idempotent, so a handle BuildKeyPairs' own
            // failure path already disposed is safely disposed again rather than leaked.
            foreach (var (label, item) in itemsByLabel)
            {
                var keptAsActiveSigningKey = returnedSuccessfully && string.Equals(label, activeLabel, StringComparison.Ordinal);
                if (!keptAsActiveSigningKey)
                    item.Dispose();
            }
        }
    }

    private ResolvedKeychainItem ResolveItem(RegisteredKeyLabel registration, int totalKeyCount)
    {
        if (registration.ActivatesAt is { } explicitActivatesAt)
        {
            var keyItem = _reader.GetKey(registration.Label);
            return new ResolvedKeychainItem
            {
                SigningKey = keyItem.SigningKey,
                KeyType = keyItem.KeyType,
                ActivatesAt = explicitActivatesAt,
                ExpiresAt = registration.ExpiresAt ?? DateTimeOffset.MaxValue,
            };
        }

        if (_reader.TryGetCertificate(registration.Label, out var certificateItem))
        {
            var subject = certificateItem.Certificate.Subject;
            var notBefore = new DateTimeOffset(certificateItem.Certificate.NotBefore);
            var notAfter = new DateTimeOffset(certificateItem.Certificate.NotAfter);
            certificateItem.Certificate.Dispose(); // Extracted the two facts we need; the signing key lives on independently.

            return new ResolvedKeychainItem
            {
                SigningKey = certificateItem.SigningKey,
                KeyType = certificateItem.KeyType,
                ActivatesAt = notBefore,
                ExpiresAt = notAfter,
                CertificateSubject = subject,
            };
        }

        var bareKeyItem = _reader.GetKey(registration.Label);
        if (totalKeyCount >= 2)
        {
            bareKeyItem.Dispose();
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "signing.macos_keychain.bare_key_requires_activation",
                $"Keychain label '{registration.Label}' resolved to a bare (certificate-less) key with " +
                "no explicit activation time, but 2 or more keys are registered in total. Register it " +
                $"via options.AddKey(\"{registration.Label}\", activatesAt) instead, giving it an " +
                "explicit activation time so its position in the rotation timeline is unambiguous. " +
                "(A bare key with no explicit activation is only valid when it is the sole registered key.)"));
        }

        return new ResolvedKeychainItem
        {
            SigningKey = bareKeyItem.SigningKey,
            KeyType = bareKeyItem.KeyType,
            ActivatesAt = DateTimeOffset.MinValue,
            ExpiresAt = DateTimeOffset.MaxValue,
        };
    }

    private static List<SigningKeyPair> BuildKeyPairs(
        IReadOnlyList<RotationEntry> included, RotationEntry active,
        IReadOnlyDictionary<string, ResolvedKeychainItem> itemsByLabel, SigningAlgorithm algorithm)
    {
        var keyPairs = new List<SigningKeyPair>(included.Count);
        try
        {
            foreach (var entry in included)
            {
                var label = entry.Key.Id;
                var item = itemsByLabel[label];
                var isActive = string.Equals(label, active.Key.Id, StringComparison.Ordinal);

                var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
                    item.SigningKey,
                    item.KeyType,
                    algorithm,
                    "signing.macos_keychain.algorithm_key_type_mismatch",
                    mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                        ? $"MacOsKeychainSigningOptions.Algorithm is {algorithm}, but Keychain item " +
                          $"'{label}' is an RSA key. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                        : $"MacOsKeychainSigningOptions.Algorithm is {algorithm}, but Keychain item " +
                          $"'{label}' is an EC key. Use an EC algorithm (ES256, ES384, or ES512).");

                var signingKey = isActive ? item.SigningKey : BuildPublicOnlyKey(item.KeyType, descriptor);
                keyPairs.Add(new SigningKeyPair { Descriptor = descriptor, PrivateKey = signingKey });
            }
        }
        catch
        {
            foreach (var pair in keyPairs)
                pair.PrivateKey.Dispose();
            throw;
        }

        return keyPairs;
    }

    private static AsymmetricAlgorithm BuildPublicOnlyKey(SigningKeyType keyType, SigningKeyDescriptor descriptor)
    {
        if (keyType == SigningKeyType.Rsa)
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(descriptor.RsaPublicParameters!.Value);
            return rsa;
        }

        var ecdsa = ECDsa.Create();
        ecdsa.ImportParameters(descriptor.EcPublicParameters!.Value);
        return ecdsa;
    }

    private void LogKeyStatuses(
        IReadOnlyList<RotationEntry> timeline, RotationEntry active, IReadOnlyList<RotationEntry> included,
        DateTimeOffset now, TimeSpan refreshInterval, TimeSpan retirementWindow,
        IReadOnlyDictionary<string, ResolvedKeychainItem> itemsByLabel)
    {
        // Re-evaluated and logged on every LoadKeysAsync call (at most once per RefreshInterval),
        // exactly like the Windows Certificate Store provider — active/included status is a function
        // of `now` and genuinely changes as a rotation progresses, unlike the other per-item facts
        // (label, key type, key size) which never change once discovered.
        var includedLabels = new HashSet<string>(included.Select(e => e.Key.Id), StringComparer.Ordinal);

        foreach (var entry in timeline)
        {
            var item = itemsByLabel[entry.Key.Id];
            var status = DescribeStatus(entry, active, includedLabels, now, retirementWindow);

            _logger.LogInformation(
                "ZeeKayDa.Auth: macOS Keychain signing item '{Label}' ({KeyType}, {KeySize} bits{Certificate}) is {Status}.",
                entry.Key.Id, item.KeyType, item.SigningKey.KeySize,
                item.CertificateSubject is { } subject ? $", certificate subject '{subject}'" : string.Empty,
                status);
        }

        if (SigningKeyRotation.HasTooSoonPendingActivation(timeline, active, now, refreshInterval, out var soonestPending))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: Keychain item '{Label}' activates at {ActivatesAt:O}, which is less than " +
                "RefreshInterval ({RefreshInterval}) away from now. A relying party polling the JWKS at " +
                "RefreshInterval cadence may not have observed this item's public key before it starts " +
                "signing. Schedule this item's activation at least RefreshInterval in the future next " +
                "time (see ADR 0011 §3.5 / issue #282).",
                soonestPending!.Value.Key.Id, soonestPending.Value.ActivatesAt, refreshInterval);
        }
    }

    private static string DescribeStatus(
        RotationEntry entry, RotationEntry active, HashSet<string> includedLabels, DateTimeOffset now, TimeSpan retirementWindow)
    {
        if (string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal))
            return "the active signer";

        if (!includedLabels.Contains(entry.Key.Id))
        {
            return "NOT included in the JWKS - its retirement window has fully elapsed; safe to remove " +
                "from configuration";
        }

        if (entry.ActivatesAt > now)
            return $"included in the JWKS, not yet active (activates at {entry.ActivatesAt:O})";

        return "included in the JWKS, retired but still within its retirement window (until " +
            $"{entry.RetiredAt!.Value + retirementWindow:O})";
    }

    private void WarnIfActiveKeyExpiringSoon(RotationEntry active, DateTimeOffset now)
    {
        if (active.Key.ExpiresAt == DateTimeOffset.MaxValue)
            return; // Never-expiring bare key (no expiresAt was given) — nothing to warn about.

        if (active.Key.ExpiresAt - now <= TimeSpan.FromDays(30))
        {
            _logger.LogWarning(
                "ZeeKayDa.Auth: the active macOS Keychain signing item '{Label}' expires at {ExpiresAt:O}, " +
                "within 30 days. Rotate in a new key or certificate (via AddKey) before it expires.",
                active.Key.Id, active.Key.ExpiresAt);
        }
    }
}
