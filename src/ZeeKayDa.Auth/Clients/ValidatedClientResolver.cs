using System.Runtime.CompilerServices;
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
/// Verdicts are memoized per registration <em>instance</em>: a repository that caches its
/// objects pays validation once, and one returning fresh instances per lookup revalidates
/// automatically when the underlying data changes.
/// </para>
/// </remarks>
internal sealed class ValidatedClientResolver
{
    private readonly IClientRepository _repository;
    private readonly IClientRegistrationValidator _validator;
    private readonly ISanitizingLogger<ValidatedClientResolver> _logger;
    private readonly ConditionalWeakTable<IClientRegistration, Verdict> _verdicts = new();

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

        var verdict = _verdicts.GetValue(client, Validate);
        if (verdict.IsValid)
            return client;

        _logger.LogCritical(
            "Client registration for '{ClientId}' failed validation and was served to the protocol as an unknown client. " +
            "Fix the registration in the client store. Violations: {Violations}",
            client.ClientId,
            verdict.Violations);
        return null;
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
    }

    private sealed class Verdict
    {
        public static readonly Verdict Valid = new(null);

        public Verdict(string? violations) => Violations = violations;

        public string? Violations { get; }

        public bool IsValid => Violations is null;
    }
}
