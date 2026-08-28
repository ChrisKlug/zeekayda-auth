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
/// </remarks>
internal sealed class ValidatedClientResolver
{
    private readonly IClientRepository _repository;
    private readonly IClientRegistrationValidator _validator;
    private readonly ISanitizingLogger<ValidatedClientResolver> _logger;
    private readonly ConcurrentDictionary<string, Verdict> _verdicts = new(StringComparer.Ordinal);

    // Generous next to any realistic client count, and bounded so a long-lived process that
    // reconfigures clients repeatedly cannot grow the cache without limit.
    private const int MaxCachedVerdicts = 1024;

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
    /// Returns the validated registration for <paramref name="clientId"/>, or
    /// <see langword="null"/> when the client is unknown <em>or</em> its registration fails
    /// validation. Callers cannot and must not distinguish the two.
    /// </summary>
    public async ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientId);

        var client = await _repository.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return null;

        var verdict = GetOrAddVerdict(client);
        if (verdict.IsValid)
            return client;

        // Logged once per memoized verdict, not per request — a known-bad client_id must not be
        // an unauthenticated log-amplification lever.
        if (verdict.MarkLogged())
        {
            _logger.LogCritical(
                "Client registration for '{ClientId}' failed validation and was served to the protocol as an unknown client. " +
                "Fix the registration in the client store. Violations: {Violations}",
                client.ClientId,
                verdict.Violations);
        }

        return null;
    }

    private Verdict GetOrAddVerdict(IClientRegistration client)
    {
        var fingerprint = ClientRegistrationFingerprint.Compute(client);

        if (_verdicts.TryGetValue(fingerprint, out var cached))
            return cached;

        var verdict = Validate(client);

        if (_verdicts.Count >= MaxCachedVerdicts)
            _verdicts.Clear();

        return _verdicts.GetOrAdd(fingerprint, verdict);
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
            return new Verdict($"The registration validator threw {ex.GetType().Name}: {ex.Message}");
        }
    }

    private sealed class Verdict
    {
        public static readonly Verdict Valid = new(null);

        private int _logged;

        public Verdict(string? violations) => Violations = violations;

        public string? Violations { get; }

        public bool IsValid => Violations is null;

        /// <summary>Returns <see langword="true"/> exactly once per verdict instance.</summary>
        public bool MarkLogged() => Interlocked.Exchange(ref _logged, 1) == 0;
    }
}
