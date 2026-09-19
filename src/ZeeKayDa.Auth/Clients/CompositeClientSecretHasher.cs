using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Internal coordinator that dispatches secret verification and creation across all registered
/// <see cref="IClientSecretHasher"/> implementations and enforces timing-oracle mitigations.
/// </summary>
/// <remarks>
/// Registered as the concrete type <see cref="CompositeClientSecretHasher"/> — NOT as
/// <see cref="IClientSecretHasher"/> — to prevent self-injection through
/// <see cref="IEnumerable{T}"/>, which would cause infinite recursion on first verify.
/// <c>PadTiming()</c> fires on failure when the matched hasher is not the default hasher, so a
/// faster custom hasher cannot reopen a timing oracle. Every padding verification runs against
/// <c>_timingDecoy</c>, which the default hasher builds once, in the constructor; see
/// <see cref="IClientSecretHasher.CreateTimingDecoy"/> for what that costs.
/// </remarks>
internal sealed class CompositeClientSecretHasher : IClientSecretFactory
{
    /// <summary>
    /// Maximum number of active shared-secret credentials a client may have simultaneously
    /// (credential rotation window). Failure paths pad to this many verification-equivalent
    /// operations so a client in a rotation window is not distinguishable from an unknown
    /// client by timing.
    /// </summary>
    internal const int MaxActiveSharedSecretsPerClient = 2;

    /// <summary>
    /// The value every padding verification presents: fixed-length and non-empty, matching a
    /// typical client secret's length.
    /// </summary>
    internal const string DummyPresented = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 32 chars

    private readonly IReadOnlyList<IClientSecretHasher> _hashers;
    private readonly IClientSecretHasher _default;
    private readonly IClientSecret _timingDecoy;

    public CompositeClientSecretHasher(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherRegistrationOptions> registrationOptions)
    {
        ArgumentNullException.ThrowIfNull(hashers);
        ArgumentNullException.ThrowIfNull(registrationOptions);

        var hasherList = hashers.ToList();
        _hashers = hasherList;
        _default = ResolveDefault(hasherList, registrationOptions.Value);
        _timingDecoy = CreateTimingDecoy(_default);
    }

    /// <summary>
    /// Verifies a presented plaintext secret against a stored credential, dispatching to the
    /// matching registered hasher. Pads timing on failure when the matched hasher is not the default.
    /// </summary>
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
    {
        var matched = _hashers.FirstOrDefault(h => h.CanHandle(stored));
        if (matched is null)
            return false;

        var result = matched.Verify(stored, presented);

        if (!result && !ReferenceEquals(matched, _default))
            PadTiming();

        return result;
    }

    /// <summary>
    /// Creates a new hashed credential using the default hasher.
    /// </summary>
    public IClientSecret Create(string plaintext) => _default.Create(plaintext);

    /// <summary>
    /// Returns <see langword="true"/> if any registered <see cref="IClientSecretHasher"/> reports
    /// it can handle the given credential. Used by registration validation to reject credentials
    /// that no hasher can ever verify (they would otherwise fail silently at runtime as
    /// <c>invalid_client</c>).
    /// </summary>
    internal bool CanHandleAny(IClientSecret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return _hashers.Any(h => h.CanHandle(secret));
    }

    /// <summary>
    /// Returns any registration-time failures for the given credential from its owning hasher.
    /// Credentials that no registered hasher can handle are skipped silently — the
    /// <c>client.credentials.no_hasher</c> failure is already reported by
    /// <see cref="ClientRegistrationValidator"/> before this is called.
    /// </summary>
    internal IEnumerable<ZeeKayDaConfigurationFailure> GetRegistrationFailures(
        IClientSecret credential, string clientId)
    {
        ArgumentNullException.ThrowIfNull(credential);
        var matched = _hashers.FirstOrDefault(h => h.CanHandle(credential));
        return matched?.GetRegistrationFailures(credential, clientId) ?? [];
    }

    /// <summary>
    /// Runs <see cref="MaxActiveSharedSecretsPerClient"/> default-hasher verifications against
    /// the timing decoy using the non-empty <see cref="DummyPresented"/> constant.
    /// Called by paths that have no real credentials to verify (unknown client, disallowed method,
    /// <c>none</c> fallback rejection) to pad timing to match a known-client wrong-credential failure.
    /// </summary>
    /// <remarks>
    /// <strong>Must use a non-empty presented value.</strong> <see cref="Pbkdf2ClientSecretHasher"/>
    /// short-circuits immediately when <c>presented.IsEmpty</c>, which would make this method a no-op
    /// and expose a timing oracle.
    /// </remarks>
    internal void PadToCredentialBudget()
    {
        for (var i = 0; i < MaxActiveSharedSecretsPerClient; i++)
            _default.Verify(_timingDecoy, DummyPresented.AsSpan());
    }

    /// <summary>
    /// Pads up to <see cref="MaxActiveSharedSecretsPerClient"/> verification-equivalent
    /// operations so that a client with fewer active credentials does not reveal its credential
    /// count by timing. Pass the number of credentials actually attempted.
    /// </summary>
    internal void PadFailureToCredentialBudget(int attemptedCredentials)
    {
        for (var i = attemptedCredentials; i < MaxActiveSharedSecretsPerClient; i++)
            _default.Verify(_timingDecoy, DummyPresented.AsSpan());
    }

    private void PadTiming()
        => _default.Verify(_timingDecoy, DummyPresented.AsSpan());

    /// <summary>
    /// Takes the default hasher's timing decoy, refusing one the hasher cannot verify against: every
    /// padding verification would then return at once, and the padding would pad nothing.
    /// </summary>
    private static IClientSecret CreateTimingDecoy(IClientSecretHasher hasher)
    {
        var decoy = hasher.CreateTimingDecoy();
        if (decoy is not null && hasher.CanHandle(decoy))
            return decoy;

        // Error codes below are stable API — do not rename without a semver-major bump.
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "configuration.hashers.timing_decoy_unhandled",
                $"The default IClientSecretHasher '{hasher.GetType().FullName}' returned no credential " +
                "from Create, or one its own CanHandle rejects. Failure-path timing padding verifies " +
                "against a credential the default hasher creates, and against one it cannot handle every " +
                "padding verification returns at once, which would reopen the timing oracle."));
    }

    private static IClientSecretHasher ResolveDefault(
        IReadOnlyList<IClientSecretHasher> hashers,
        ClientSecretHasherRegistrationOptions options)
    {
        // Error codes below are stable API — do not rename without a semver-major bump.
        if (hashers.Count == 0)
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.none_registered",
                    "No IClientSecretHasher implementations are registered. " +
                    "Call AddSecretsHasher<T>() on the ZeeKayDaAuthBuilder."));

        if (hashers.Count == 1)
            return hashers[0];

        var defaultReg = options.Registrations.FirstOrDefault(r => r.IsDefault);
        if (defaultReg is null)
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.no_default",
                    "Multiple IClientSecretHasher implementations are registered but none is marked as " +
                    "default. Call AddSecretsHasher<T>(isDefault: true) for exactly one hasher."));

        return hashers.FirstOrDefault(h => h.GetType() == defaultReg.HasherType)
            ?? throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.default_type_not_found",
                    $"The default hasher type '{defaultReg.HasherType.FullName}' was not found in the " +
                    "registered hasher list. This indicates a DI configuration inconsistency."));
    }
}
