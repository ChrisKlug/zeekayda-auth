using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The framework's only path from a <c>client_id</c> to a registration: copies what the repository
/// returns and serves the copy only when <see cref="IClientRegistrationValidator"/> accepts it.
/// </summary>
/// <remarks>
/// A malformed id never reaches the repository. A failing registration is served as unknown, fail-closed
/// and enumeration-safe, and logged Critical once per distinct failure, keyed by rule codes and the stored
/// <c>client_id</c>, so a bad id cannot be an unauthenticated lever on the level that pages on-call.
/// </remarks>
internal sealed class ValidatedClientResolver(
    IClientRepository repository,
    IClientRegistrationValidator validator,
    SanitizingLogger<ValidatedClientResolver> logger)
{
    // Keyed by what the store resolves, never request input; cleared wholesale at the cap.
    private const int MaxLoggedFailures = 16_384;

    private readonly ConcurrentDictionary<(string? ClientId, FailureIdentity Identity), byte> _loggedFailures = new();

    /// <summary>
    /// The validated client for <paramref name="clientId"/>, without credentials, or <see langword="null"/>
    /// when it is unknown <em>or</em> invalid; callers cannot and must not tell the two apart.
    /// </summary>
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
    /// Whether this failure is new for this registration. Unreadable registrations have no id, so they share
    /// one key per failure: almost always the same bug.
    /// </summary>
    private bool MarkLogged(string? clientId, FailureIdentity identity)
    {
        if (!_loggedFailures.TryAdd((clientId, identity), 0))
            return false;

        if (_loggedFailures.Count >= MaxLoggedFailures)
            _loggedFailures.Clear();

        return true;
    }

    /// <summary>The copy the protocol will see and what is wrong with it; no copy when it could not be read.</summary>
    private (ClientRegistrationSnapshot? Snapshot, Failure? Failure) Resolve(IClientWithCredentials client)
    {
        ClientRegistrationSnapshot snapshot;
        try
        {
            snapshot = ClientRegistrationSnapshot.Of(client);
        }
        catch (Exception ex)
        {
            // A getter may throw or a set change mid-read: answer unknown rather than a 500.
            return (null, new Failure(
                $"The registration could not be read: {ex.GetType().FullName}.",
                new FailureIdentity("unreadable", [ex.GetType().FullName ?? ex.GetType().Name])));
        }

        return (snapshot, Validate(snapshot));
    }

    private Failure? Validate(IClientWithCredentials client)
    {
        // Reading the result too: enumerating a host's list may throw.
        try
        {
            return Describe(validator.Validate(client));
        }
        catch (Exception ex)
        {
            // Fail closed. The type's FullName, never ex.Message, which a host validator may fill with anything.
            return new Failure(
                $"The registration validator threw {ex.GetType().FullName}.",
                new FailureIdentity("threw", [ex.GetType().FullName ?? ex.GetType().Name]));
        }
    }

    private static Failure? Describe(IReadOnlyList<ZeeKayDaConfigurationFailure> failures)
    {
        if (failures.Count == 0)
            return null;

        // Codes, sorted: stable across calls even when the validator rewords or reorders its messages.
        return new Failure(
            string.Join("; ", failures.Select(f => f.Message)),
            new FailureIdentity("rules", [.. failures.Select(f => f.Code).Order(StringComparer.Ordinal)]));
    }

    /// <param name="Violations">What the operator is told.</param>
    /// <param name="Identity">What suppression keys on; never the reworded-per-call message.</param>
    private sealed record Failure(string Violations, FailureIdentity Identity);

    /// <summary>
    /// What a failure is: rule codes or a thrown type, under a <paramref name="Kind"/>. Compared part by part,
    /// never joined, since host codes may contain any separator.
    /// </summary>
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
