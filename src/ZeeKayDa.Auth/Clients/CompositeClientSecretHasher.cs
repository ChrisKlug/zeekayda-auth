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
/// Every failure is padded in failed credential slots of one verification per registered hasher, each
/// against a decoy that hasher builds once, in the constructor; see
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
    private readonly IReadOnlyList<(IClientSecretHasher Hasher, IClientSecret Decoy)> _timingDecoys;

    public CompositeClientSecretHasher(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherRegistrationOptions> registrationOptions)
    {
        var hasherList = hashers.ToList();
        _hashers = hasherList;
        _default = ResolveDefault(hasherList, registrationOptions.Value);
        _timingDecoys = hasherList.Select(hasher => (hasher, CreateTimingDecoy(hasher))).ToList();
    }

    /// <summary>
    /// Verifies a presented plaintext secret against a stored credential, dispatching to the
    /// matching registered hasher. A failure spends a whole failed credential slot.
    /// </summary>
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
    {
        var matched = _hashers.FirstOrDefault(h => h.CanHandle(stored));
        if (matched is null)
            return false;

        var result = matched.Verify(stored, presented);

        if (!result)
            FinishFailedCredentialSlot(alreadyVerifiedBy: matched);

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
    /// Spends <see cref="MaxActiveSharedSecretsPerClient"/> failed credential slots, presenting the
    /// non-empty <see cref="DummyPresented"/> constant.
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
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
    }

    /// <summary>
    /// Spends the failed credential slots the client did not use, so a client with fewer active
    /// credentials does not reveal its credential count by timing. Pass the number of credentials
    /// actually attempted.
    /// </summary>
    internal void PadFailureToCredentialBudget(int attemptedCredentials)
    {
        for (var i = attemptedCredentials; i < MaxActiveSharedSecretsPerClient; i++)
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
    }

    /// <summary>
    /// A failed credential slot is one verification by every registered hasher, so its cost is the
    /// same whichever hasher's credential failed, or whether there was a credential at all.
    /// </summary>
    private void FinishFailedCredentialSlot(IClientSecretHasher? alreadyVerifiedBy)
    {
        foreach (var (hasher, decoy) in _timingDecoys)
        {
            if (!ReferenceEquals(hasher, alreadyVerifiedBy))
                hasher.Verify(decoy, DummyPresented.AsSpan());
        }
    }

    /// <summary>
    /// Takes a hasher's timing decoy, refusing one the hasher cannot verify against: every
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
                $"The IClientSecretHasher '{hasher.GetType().FullName}' returned no timing decoy, " +
                "or one its own CanHandle rejects. For a hasher that does not build its own decoy, the " +
                "decoy is what its Create returns for a random value. Failure-path timing padding " +
                "verifies against that decoy, and against one the hasher cannot handle every padding " +
                "verification returns at once, which would reopen the timing oracle."));
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
                    "Call AddClientSecretHasher<T>() on the ZeeKayDa.Auth builder."));

        if (hashers.Count == 1)
            return hashers[0];

        var defaultType = options.DefaultHasherType;
        return hashers.FirstOrDefault(h => h.GetType() == defaultType)
            ?? throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.default_type_not_found",
                    $"The default hasher type '{defaultType.FullName}' was not found in the " +
                    "registered hasher list. With no hasher marked isDefault: true the default is PBKDF2, " +
                    "so it must stay registered."));
    }
}
