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
/// A repository does not validate what it returns; this resolver does. A store fed by a typo'd or
/// malicious database row would otherwise hand the protocol an unvalidated redirect URI, and
/// exact-match redirect validation is only as trustworthy as the set it matches against.
/// Endpoints consume this type, never the repository, and being <see langword="internal"/> a host
/// cannot bypass it.
/// </para>
/// <para>
/// A malformed <c>client_id</c> is answered as unknown without calling the repository, so a
/// repository only ever sees well-formed ids.
/// </para>
/// <para>
/// A registration that fails validation is served to the protocol as unknown client
/// (<see langword="null"/>) — fail closed and enumeration-safe — while the operator, whose bug
/// it is, gets a critical log entry naming the client and the violated rules.
/// </para>
/// <para>
/// <strong>What is validated is what is served.</strong> The store's instance is copied into a
/// <see cref="ClientRegistrationSnapshot"/> before anything reads it twice, and it is the snapshot
/// that is validated and returned. A store free to edit a registration between the two would
/// otherwise have its redirect URIs approved and then matched against a different set.
/// </para>
/// <para>
/// <strong>The critical log is written once per distinct failure, not per request</strong> — a
/// known-bad <c>client_id</c> must not be an unauthenticated lever on the level that pages
/// on-call. A failure is identified by its <see cref="ZeeKayDaConfigurationFailure.Code"/> values
/// or a thrown type's name, never the free-form message, together with the <c>client_id</c>
/// <em>the store returned</em>, never the one the request asked for. A registration that breaks a
/// second, different way is a new fact and still logged.
/// </para>
/// </remarks>
internal sealed class ValidatedClientResolver(
    IClientRepository repository,
    IClientRegistrationValidator validator,
    SanitizingLogger<ValidatedClientResolver> logger)
{
    // Keyed by what the store resolves, never by request input, so its size follows the
    // deployment's real client configurations. Cleared wholesale at the cap, which costs one extra
    // log line per failing client.
    private const int MaxLoggedFailures = 16_384;

    private readonly ConcurrentDictionary<(string? ClientId, FailureIdentity Identity), byte> _loggedFailures = new();

    /// <summary>
    /// Returns the credential-free <see cref="IClient"/> view of the validated client for
    /// <paramref name="clientId"/>, or
    /// <see langword="null"/> when the client is unknown <em>or</em> its registration fails
    /// validation. Callers cannot and must not distinguish the two.
    /// </summary>
    /// <remarks>
    /// The returned instance is never the store's own — see the snapshot's remarks for why.
    /// </remarks>
    public ValueTask<IClient?> FindClientAsync(string clientId, CancellationToken cancellationToken) =>
        FindAsync<IClient>(clientId, cancellationToken);

    /// <summary>
    /// <see cref="FindClientAsync"/> with the client's credentials, for client authentication only.
    /// </summary>
    public ValueTask<IClientWithCredentials?> FindClientWithCredentialsAsync(string clientId, CancellationToken cancellationToken) =>
        FindAsync<IClientWithCredentials>(clientId, cancellationToken);

    private async ValueTask<TClient?> FindAsync<TClient>(string clientId, CancellationToken cancellationToken)
        where TClient : class, IClient
    {
        ArgumentNullException.ThrowIfNull(clientId);

        if (!ClientRegistrationValidator.IsValidClientId(clientId))
            return null;

        var client = await repository.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client is null)
            return null;

        var (snapshot, failure) = Resolve(client);
        if (failure is null)
            return snapshot as TClient;

        // The registration's own ClientId names it where it could be read; the looked-up one is
        // all there is where it could not.
        if (MarkLogged(snapshot?.ClientId, failure.Identity))
        {
            logger.LogCritical(
                "Client registration for '{ClientId}' failed validation and was served to the protocol as an unknown client. " +
                "Fix the registration in the client store. Violations: {Violations}",
                snapshot?.ClientId ?? clientId,
                failure.Violations);
        }

        return null;
    }

    /// <summary>
    /// Returns <see langword="true"/> the first time a given failure is seen for a given
    /// registration, and <see langword="false"/> for every repeat of it.
    /// </summary>
    /// <remarks>
    /// A registration that could not be read has no <c>client_id</c>, so every unreadable
    /// registration failing the same way shares one key and only the first is logged — almost
    /// always the same bug, and the entry names the looked-up id and the exception type.
    /// </remarks>
    private bool MarkLogged(string? clientId, FailureIdentity identity)
    {
        if (!_loggedFailures.TryAdd((clientId, identity), 0))
            return false;

        if (_loggedFailures.Count >= MaxLoggedFailures)
            _loggedFailures.Clear();

        return true;
    }

    /// <summary>
    /// The copy of <paramref name="client"/> the protocol will see, and what is wrong with it, if
    /// anything. The snapshot is <see langword="null"/> only when the registration could not be
    /// read at all.
    /// </summary>
    private (ClientRegistrationSnapshot? Snapshot, Failure? Failure) Resolve(IClientWithCredentials client)
    {
        ClientRegistrationSnapshot snapshot;
        try
        {
            snapshot = ClientRegistrationSnapshot.Of(client);
        }
        catch (Exception ex)
        {
            // A registration is an extension point: a property getter may throw, or a set may be
            // mutated while it is being read. Either way answer unknown rather than let a 500
            // escape from every protocol endpoint.
            return (null, new Failure(
                $"The registration could not be read: {ex.GetType().FullName}.",
                new FailureIdentity("unreadable", [ex.GetType().FullName ?? ex.GetType().Name])));
        }

        return (snapshot, Validate(snapshot));
    }

    private Failure? Validate(IClientWithCredentials client)
    {
        // Reading the result is inside the try too: a host's list is an extension point, and
        // enumerating it may throw.
        try
        {
            return Describe(validator.Validate(client));
        }
        catch (Exception ex)
        {
            // Fail closed on a buggy validator too. The exception TYPE is named, never ex.Message:
            // a caller-supplied validator can throw anything, and this text is logged. FullName, so
            // two vendors' ValidationException stay distinguishable.
            return new Failure(
                $"The registration validator threw {ex.GetType().FullName}.",
                new FailureIdentity("threw", [ex.GetType().FullName ?? ex.GetType().Name]));
        }
    }

    private static Failure? Describe(IReadOnlyList<ZeeKayDaConfigurationFailure?>? failures)
    {
        if (failures is null || failures.Any(failure => failure is null))
        {
            return new Failure(
                "The registration validator returned a null list or a null failure.",
                new FailureIdentity("malformed", []));
        }

        if (failures.Count == 0)
            return null;

        // Codes are a documented stable contract, so they identify the same failure across calls
        // even when the validator rewords its message. Sorted so the same rules reported in a
        // different order are the same failure.
        return new Failure(
            string.Join("; ", failures.Select(f => f!.Message)),
            new FailureIdentity("rules", [.. failures.Select(f => f!.Code).Order(StringComparer.Ordinal)]));
    }

    /// <param name="Violations">What the operator is told.</param>
    /// <param name="Identity">What suppression keys on; never the reworded-per-call message.</param>
    private sealed record Failure(string Violations, FailureIdentity Identity);

    /// <summary>
    /// What a failure <em>is</em>: rule codes or a thrown type's name, under a
    /// <paramref name="Kind"/> that keeps the sources apart.
    /// </summary>
    /// <remarks>
    /// Compared part by part, never joined into one string: a rule code is host-supplied with no
    /// syntax restriction, so <c>["a; b", "c"]</c> and <c>["a", "b; c"]</c> would join the same.
    /// </remarks>
    private sealed record FailureIdentity(string Kind, IReadOnlyList<string> Parts)
    {
        public bool Equals(FailureIdentity? other) =>
            other is not null
            && string.Equals(Kind, other.Kind, StringComparison.Ordinal)
            && Parts.SequenceEqual(other.Parts, StringComparer.Ordinal);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Kind, StringComparer.Ordinal);
            foreach (var part in Parts)
                hash.Add(part, StringComparer.Ordinal);

            return hash.ToHashCode();
        }
    }
}
