using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The framework's only path from a <c>client_id</c> to a client registration. Wraps the
/// registered <see cref="IClientRepository"/> and refuses to serve any registration that fails
/// <see cref="IClientRegistrationValidator"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IClientRepository"/> documents that custom stores MUST validate registrations
/// before serving them, but nothing enforces that contract — a store fed by a typo'd or
/// malicious database row would otherwise hand the protocol an unvalidated redirect URI, and
/// exact-match redirect validation is only as trustworthy as the set it matches against. This
/// resolver makes the guarantee structural: endpoints consume this type, never the repository,
/// and being <see langword="internal"/> a host cannot bypass it.
/// </para>
/// <para>
/// A registration that fails validation is served to the protocol as unknown client
/// (<see langword="null"/>) — fail closed and enumeration-safe — while the operator, whose bug
/// it is, gets a critical log entry naming the client and the violated rules.
/// </para>
/// <para>
/// <strong>What is validated is what is served.</strong> The store's instance is copied into a
/// <see cref="ClientRegistrationSnapshot"/> before anything reads it twice, and it is the snapshot
/// that is fingerprinted, validated and returned. A store free to edit a registration between the
/// two would otherwise have its redirect URIs approved and then matched against a different set.
/// </para>
/// <para>
/// <strong>Verdicts are memoized by registration content, not by instance.</strong> Validation
/// runs a full PBKDF2 derivation (the empty-secret probe), so revalidating on every lookup would
/// make an unauthenticated request to a protocol endpoint cost hundreds of milliseconds of CPU —
/// a denial-of-service amplifier keyed on a public <c>client_id</c>. Content keying means a store
/// that hands out fresh instances per lookup still pays validation only once per distinct
/// configuration, while a store that mutates a cached registration in place is picked up
/// automatically because its fingerprint changes. See <see cref="ClientRegistrationFingerprint"/>.
/// </para>
/// <para>
/// The verdict cache is bounded. Its keys come from registrations the store returns — never from
/// request input — so its size follows the deployment's real client configurations and cannot be
/// grown by a caller. On reaching the cap the cache is cleared wholesale rather than evicting
/// selectively; at this size that is a rare event, and the cost is one revalidation per client.
/// </para>
/// <para>
/// <strong>The critical log is suppressed separately from the verdict cache.</strong> Two paths
/// answer without a cached verdict — a registration that could not be read at all, and one whose
/// fingerprint is not content-addressable — so a verdict's own "already logged" flag left both
/// writing a critical entry per request, which is an unauthenticated log-amplification lever
/// aimed at the level that pages on-call. Suppression is therefore keyed by <c>client_id</c> and
/// the violation text together: a registration that breaks a second, different way is a new fact
/// and still logged, while a repeat of the same failure is silent. That set is bounded and
/// cleared the same way, and a clear costs one extra log line per client rather than a PBKDF2.
/// </para>
/// </remarks>
internal sealed class ValidatedClientResolver
{
    private readonly IClientRepository _repository;
    private readonly IClientRegistrationValidator _validator;
    private readonly ISanitizingLogger<ValidatedClientResolver> _logger;
    private readonly ConcurrentDictionary<string, Lazy<Verdict>> _verdicts = new(StringComparer.Ordinal);

    // Failures already written to the critical log, so a repeat of one is not written again. Held
    // apart from _verdicts because the two paths that most need suppressing never reach that cache.
    // Bounded by the same cap: an entry is a short string, and the two sets are the same order of
    // magnitude because both are keyed by things the store resolves.
    private readonly ConcurrentDictionary<string, byte> _loggedFailures = new(StringComparer.Ordinal);

    // Sized for a multi-tenant deployment: each entry is a fingerprint string plus a verdict
    // reference, so the ceiling costs on the order of a megabyte. Undersizing this is not a
    // tidiness issue — past the cap the hit rate collapses and every miss is a full PBKDF2,
    // re-arming the denial-of-service this cache exists to prevent.
    private const int MaxCachedVerdicts = 16_384;

    public ValidatedClientResolver(
        IClientRepository repository,
        IClientRegistrationValidator validator,
        ISanitizingLogger<ValidatedClientResolver> logger)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(validator);
        ArgumentNullException.ThrowIfNull(logger);

        _repository = repository;
        _validator = validator;
        _logger = logger;
    }

    /// <summary>
    /// Returns an immutable snapshot of the validated registration for <paramref name="clientId"/>,
    /// or <see langword="null"/> when the client is unknown <em>or</em> its registration fails
    /// validation. Callers cannot and must not distinguish the two.
    /// </summary>
    /// <remarks>
    /// The returned instance is never the store's own, and neither are its credentials — see the
    /// snapshot's remarks for why.
    /// </remarks>
    public async ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        var client = await _repository.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return null;

        var (snapshot, verdict) = Resolve(client);
        if (snapshot is not null && verdict.IsValid)
            return snapshot;

        // Logged once per distinct failure, not per request — a known-bad client_id must not be
        // an unauthenticated log-amplification lever. The registration's own ClientId is what
        // names it where it could be read; the looked-up one is all there is where it could not.
        var loggedClientId = snapshot?.ClientId ?? clientId;
        if (MarkLogged(loggedClientId, verdict.Violations))
        {
            _logger.LogCritical(
                "Client registration for '{ClientId}' failed validation and was served to the protocol as an unknown client. " +
                "Fix the registration in the client store. Violations: {Violations}",
                loggedClientId,
                verdict.Violations);
        }

        return null;
    }

    /// <summary>
    /// Returns <see langword="true"/> the first time a given failure is seen for a given
    /// <c>client_id</c>, and <see langword="false"/> for every repeat of it.
    /// </summary>
    /// <remarks>
    /// Neither half of the key is caller-controlled: the store decides which <c>client_id</c>s
    /// resolve to a registration at all, and the violation text is the validator's own message or
    /// the type name of what it threw. A deployment large enough to reach the cap pays one further
    /// critical entry per failing registration after the clear.
    /// </remarks>
    private bool MarkLogged(string clientId, string? violations)
    {
        if (!_loggedFailures.TryAdd($"{clientId}\n{violations}", 0))
            return false;

        if (_loggedFailures.Count >= MaxCachedVerdicts)
            _loggedFailures.Clear();

        return true;
    }

    /// <summary>
    /// The copy of <paramref name="client"/> the protocol will see, and the verdict on it. The
    /// snapshot is <see langword="null"/> only when the registration could not be read at all,
    /// which the verdict then says.
    /// </summary>
    private (ClientRegistrationSnapshot? Snapshot, Verdict Verdict) Resolve(IClientRegistration client)
    {
        ClientRegistrationSnapshot snapshot;
        ClientRegistrationFingerprint.Fingerprint fingerprint;
        try
        {
            // Copied before it is fingerprinted, and never read through again: the values the
            // verdict is about are exactly the values the caller gets. See the snapshot's remarks.
            snapshot = ClientRegistrationSnapshot.Of(client);
            fingerprint = ClientRegistrationFingerprint.Compute(snapshot);
        }
        catch (ClientRegistrationSnapshot.UncopiedCredentialException ex)
        {
            // A registration the snapshot refused to copy — a null credential, or one whose
            // Snapshot() handed back itself or null. The failure is the snapshot's own text, so it is
            // named; anything
            // else thrown here, a ZeeKayDaConfigurationException included, is reduced to its type.
            return (null, new Verdict(ex.Failure.Message));
        }
        catch (Exception ex)
        {
            // A registration is an extension point: a property getter may throw, or a set may be
            // mutated while it is being read. Either way this type's promise is to answer unknown
            // rather than let a 500 escape from every protocol endpoint.
            return (null, new Verdict($"The registration could not be read: {ex.GetType().FullName}."));
        }

        return (snapshot, GetOrAddVerdict(snapshot, fingerprint));
    }

    private Verdict GetOrAddVerdict(ClientRegistrationSnapshot client, ClientRegistrationFingerprint.Fingerprint fingerprint)
    {
        // An instance-identity fallback (a custom IClientCredential) produces a different key for
        // every instance of the same registration. Caching under it would let request volume grow
        // the cache — the one thing the bound must not depend on — so it is validated uncached.
        // The cost lands only on that registration, not on every other client's cached verdict.
        if (!fingerprint.IsContentAddressable)
            return Validate(client);

        // Lazy with ExecutionAndPublication so a burst of concurrent first-requests for one
        // client runs the 600,000-iteration derivation once rather than once per request.
        var entry = _verdicts.GetOrAdd(
            fingerprint.Value,
            _ => new Lazy<Verdict>(() => Validate(client), LazyThreadSafetyMode.ExecutionAndPublication));

        if (_verdicts.Count >= MaxCachedVerdicts)
        {
            // Logged so the cliff is visible: after a clear, every client revalidates once, and a
            // deployment hitting this repeatedly is paying PBKDF2 far more often than it should.
            _logger.LogWarning(
                "The client validation cache reached its {Cap}-entry limit and was cleared. " +
                "Every registration will be revalidated once, which is CPU-intensive.",
                MaxCachedVerdicts);
            _verdicts.Clear();
        }

        return entry.Value;
    }

    private Verdict Validate(IClientRegistration client)
    {
        try
        {
            _validator.Validate(client);
            return Verdict.Valid;
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            return new Verdict(string.Join("; ", ex.AggregatedFailures.Select(f => f.Message)));
        }
        catch (Exception ex)
        {
            // A validator throwing anything else is a bug in the extension point, but the promise
            // of this type is fail-closed: the registration must still answer as unknown rather
            // than escape as a 500 from every protocol endpoint.
            // The exception TYPE is named, never ex.Message. A caller-supplied validator can throw
            // anything, and a Verdict's text is surfaced and logged. FullName, not Name: two vendors'
            // ValidationException would otherwise be indistinguishable to the operator reading it.
            return new Verdict($"The registration validator threw {ex.GetType().FullName}.");
        }
    }

    private sealed class Verdict
    {
        public static readonly Verdict Valid = new(null);

        public Verdict(string? violations) => Violations = violations;

        public string? Violations { get; }

        public bool IsValid => Violations is null;
    }
}
