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
/// faster custom hasher cannot reopen a timing oracle. The constructor's ~600 ms cost to
/// pre-compute <c>_dummySecret</c> via PBKDF2 at 600,000 iterations is intentional, paid once at
/// host startup.
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

    // Fixed-length non-empty dummy presented value, matching a typical client secret's length.
    private const string DummyPresented = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 32 chars

    private readonly IReadOnlyList<IClientSecretHasher> _hashers;
    private readonly IClientSecretHasher _default;
    private readonly IClientSecret _dummySecret;

    public CompositeClientSecretHasher(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherRegistrationOptions> registrationOptions)
    {
        ArgumentNullException.ThrowIfNull(hashers);
        ArgumentNullException.ThrowIfNull(registrationOptions);

        var hasherList = hashers.ToList();
        _hashers = hasherList;
        _default = ResolveDefault(hasherList, registrationOptions.Value);

        // Pre-computed via the default hasher so its parameters match a real verification.
        _dummySecret = _default.Create(DummyPresented);
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
    /// Runs one default-hasher verification against the pre-computed dummy secret.
    /// Called by the token endpoint for unknown-client paths to pad timing to match
    /// a known-client wrong-credential failure.
    /// </summary>
    internal bool VerifyUnknownClientForTimingOnly(ReadOnlySpan<char> presented)
        => _default.Verify(_dummySecret, presented);

    /// <summary>
    /// Runs <see cref="MaxActiveSharedSecretsPerClient"/> default-hasher verifications against
    /// the pre-computed dummy secret using the non-empty <c>DummyPresented</c> constant.
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
            _default.Verify(_dummySecret, DummyPresented.AsSpan());
    }

    /// <summary>
    /// Pads up to <see cref="MaxActiveSharedSecretsPerClient"/> verification-equivalent
    /// operations so that a client with fewer active credentials does not reveal its credential
    /// count by timing. Pass the number of credentials actually attempted.
    /// </summary>
    internal void PadFailureToCredentialBudget(int attemptedCredentials)
    {
        for (var i = attemptedCredentials; i < MaxActiveSharedSecretsPerClient; i++)
            _default.Verify(_dummySecret, DummyPresented.AsSpan());
    }

    private void PadTiming()
        => _default.Verify(_dummySecret, DummyPresented.AsSpan());

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
