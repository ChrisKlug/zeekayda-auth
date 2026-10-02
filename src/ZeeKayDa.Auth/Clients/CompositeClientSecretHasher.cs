using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Internal coordinator that dispatches secret verification and creation across all registered
/// <see cref="IClientSecretHasher"/> implementations by algorithm id, enforces the rules every
/// hasher is held to, and pads failures against timing oracles.
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
    /// Maximum number of active secrets a client may have simultaneously (rotation window). Failure
    /// paths pad to this many verification-equivalent operations so a client in a rotation window
    /// is not distinguishable from an unknown client by timing.
    /// </summary>
    internal const int MaxActiveSharedSecretsPerClient = 2;

    /// <summary>
    /// The value every padding verification presents: fixed-length and non-empty, matching a
    /// typical client secret's length.
    /// </summary>
    internal const string DummyPresented = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // 32 chars

    private readonly IReadOnlyDictionary<string, IClientSecretHasher> _hashersById;
    private readonly IClientSecretHasher _default;
    private readonly IReadOnlyList<(IClientSecretHasher Hasher, ClientSecret Decoy)> _timingDecoys;
    private readonly SanitizingLogger<CompositeClientSecretHasher> _logger;
    private readonly ConcurrentDictionary<Type, byte> _loggedThrowingHashers = new();

    public CompositeClientSecretHasher(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherRegistrationOptions> registrationOptions,
        SanitizingLogger<CompositeClientSecretHasher> logger)
    {
        var hasherList = hashers.ToList();
        _logger = logger;
        _default = ResolveDefault(hasherList, registrationOptions.Value);
        _hashersById = IndexByAlgorithmId(hasherList);
        _timingDecoys = hasherList.Select(hasher => (hasher, CreateTimingDecoy(_hashersById, hasher))).ToList();
    }

    /// <summary>
    /// The algorithm id of a stored value: the text between its first two <c>$</c>, or
    /// <see langword="null"/> when the value does not start with <c>$&lt;id&gt;$</c> or that text could
    /// not be an id. Only an id this returns is ever written to a log.
    /// </summary>
    internal static string? AlgorithmIdOf(string? value)
    {
        if (value is null || !value.StartsWith('$'))
            return null;

        var end = value.IndexOf('$', 1);
        return end > 1 && value[1..end] is var id && PhcString.IsName(id) ? id : null;
    }

    /// <summary>
    /// Verifies a presented plaintext secret against a stored one, dispatching to the hasher that
    /// declared its algorithm id. A failure spends a whole failed credential slot.
    /// </summary>
    public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
    {
        var owner = OwnerOf(stored);
        if (owner is null)
        {
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
            return false;
        }

        var outcome = SafeVerify(owner, stored, presented);
        if (outcome is true)
            return true;

        // A hasher that threw may have stopped before doing its work, so its decoy is spent too.
        FinishFailedCredentialSlot(alreadyVerifiedBy: outcome is false ? owner : null);
        return false;
    }

    /// <summary>
    /// What is wrong if the stored secret's own hasher verifies an empty presented secret, or throws
    /// trying. A registration check, not an authentication, so it spends no failed credential slot
    /// and a throw is the operator's failure to read, not a request-time log entry.
    /// </summary>
    internal ZeeKayDaConfigurationFailure? EmptySecretProblem(ClientSecret stored, string clientId)
    {
        if (OwnerOf(stored) is not { } owner)
            return null;

        try
        {
            return owner.Verify(stored, ReadOnlySpan<char>.Empty)
                ? new ZeeKayDaConfigurationFailure(
                    "client.credentials.empty_secret_accepted",
                    $"A secret for client '{clientId}' accepts an empty presented secret. " +
                    "Secrets must not accept empty input — this would allow unauthenticated access " +
                    "to the client. Review the stored secret and the associated hasher.")
                : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never ex.Message: it is the hasher's text, and failure messages are logged verbatim.
            return new ZeeKayDaConfigurationFailure(
                "client.credentials.verify_threw",
                $"Client '{clientId}': the IClientSecretHasher '{owner.GetType().FullName}' threw " +
                $"{ex.GetType().FullName} verifying a stored secret, so the client could never authenticate.");
        }
    }

    /// <inheritdoc/>
    public ClientSecret Create(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Create(plaintext.AsSpan());
    }

    /// <inheritdoc/>
    public ClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        if (plaintext.IsWhiteSpace())
            throw new ArgumentException("Secret must not be empty or whitespace.", nameof(plaintext));

        var created = _default.Create(plaintext)
            ?? throw new InvalidOperationException(
                $"The IClientSecretHasher '{_default.GetType().FullName}' returned null from Create.");

        return IsOwnOutput(_hashersById, _default, created)
            ? created
            : throw new InvalidOperationException(
                $"The IClientSecretHasher '{_default.GetType().FullName}' created a secret whose algorithm id " +
                "is not one of its AlgorithmIds, so no registered hasher would verify it.");
    }

    /// <summary>
    /// Whether a registered hasher declared the stored value's algorithm id.
    /// </summary>
    internal bool CanVerify(ClientSecret stored) => OwnerOf(stored) is not null;

    /// <summary>
    /// The owning hasher's failures for a stored secret, each prefixed with the client id. A hasher
    /// that throws is reported by exception type. A secret no hasher declared yields nothing here:
    /// the validator reports <c>client.credentials.no_hasher</c> for it.
    /// </summary>
    internal IReadOnlyList<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored, string clientId)
    {
        var owner = OwnerOf(stored);
        if (owner is null)
            return [];

        try
        {
            return owner.ValidateStoredSecret(stored) is { } failures
                ? PrefixedWith(clientId, failures)
                :
                [
                    new ZeeKayDaConfigurationFailure(
                        "client.credentials.validation_returned_null",
                        $"Client '{clientId}': the IClientSecretHasher '{owner.GetType().FullName}' returned null " +
                        "from ValidateStoredSecret; it returns an empty sequence for an acceptable secret."),
                ];
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // The hasher's own coded failures, on the same terms as ones it returned.
            return PrefixedWith(clientId, ex.AggregatedFailures);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never ex.Message: it is the hasher's text, and failure messages are logged verbatim.
            return
            [
                new ZeeKayDaConfigurationFailure(
                    "client.credentials.validation_threw",
                    $"Client '{clientId}': the IClientSecretHasher '{owner.GetType().FullName}' threw " +
                    $"{ex.GetType().FullName} validating a stored secret."),
            ];
        }
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> PrefixedWith(
        string clientId, IEnumerable<ZeeKayDaConfigurationFailure> failures) =>
    [
        .. failures
            .OfType<ZeeKayDaConfigurationFailure>()
            .Select(failure => failure with { Message = $"Client '{clientId}': {failure.Message}" }),
    ];

    /// <summary>
    /// Spends <see cref="MaxActiveSharedSecretsPerClient"/> failed credential slots, presenting the
    /// non-empty <see cref="DummyPresented"/> constant.
    /// Called by paths that have no real secrets to verify (unknown client, disallowed method,
    /// <c>none</c> fallback rejection) to pad timing to match a known-client wrong-secret failure.
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
    /// secrets does not reveal its secret count by timing. Pass the number of secrets actually
    /// attempted.
    /// </summary>
    internal void PadFailureToCredentialBudget(int attemptedCredentials)
    {
        for (var i = attemptedCredentials; i < MaxActiveSharedSecretsPerClient; i++)
            FinishFailedCredentialSlot(alreadyVerifiedBy: null);
    }

    /// <summary>
    /// A failed credential slot is one verification by every registered hasher, so its cost is the
    /// same whichever hasher's secret failed, or whether there was a secret at all.
    /// </summary>
    private void FinishFailedCredentialSlot(IClientSecretHasher? alreadyVerifiedBy)
    {
        foreach (var (hasher, decoy) in _timingDecoys)
        {
            if (!ReferenceEquals(hasher, alreadyVerifiedBy))
                SafeVerify(hasher, decoy, DummyPresented.AsSpan());
        }
    }

    private IClientSecretHasher? OwnerOf(ClientSecret? stored) =>
        AlgorithmIdOf(stored?.Value) is { } id ? _hashersById.GetValueOrDefault(id) : null;

    // Checked against the ids indexed at startup, never the hasher's live AlgorithmIds: a set that
    // changed since would let through a secret dispatch can never route back to this hasher.
    private static bool IsOwnOutput(
        IReadOnlyDictionary<string, IClientSecretHasher> hashersById, IClientSecretHasher hasher, ClientSecret? created) =>
        AlgorithmIdOf(created?.Value) is { } id
        && hashersById.TryGetValue(id, out var owner)
        && ReferenceEquals(owner, hasher);

    /// <summary>
    /// The hasher's answer, or <see langword="null"/> when it threw, which fails the verification.
    /// Logged once per hasher type, by exception type only: the trigger is a request, so logging
    /// every throw would be an unauthenticated log-amplification lever.
    /// </summary>
    private bool? SafeVerify(IClientSecretHasher hasher, ClientSecret stored, ReadOnlySpan<char> presented)
    {
        try
        {
            return hasher.Verify(stored, presented);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (_loggedThrowingHashers.TryAdd(hasher.GetType(), 0))
            {
                _logger.LogError(
                    "The IClientSecretHasher '{Hasher}' threw {ExceptionType} from Verify; the verification failed. " +
                    "Verify must return false rather than throw. Further throws from this hasher are not logged.",
                    hasher.GetType().FullName,
                    ex.GetType().FullName);
            }

            return null;
        }
    }

    private static IReadOnlyDictionary<string, IClientSecretHasher> IndexByAlgorithmId(
        IReadOnlyList<IClientSecretHasher> hashers)
    {
        var failures = hashers
            .SelectMany(hasher => DeclarationRules.Select(rule => rule(hasher)))
            .OfType<ZeeKayDaConfigurationFailure>()
            .ToList();

        var byId = new Dictionary<string, IClientSecretHasher>(StringComparer.Ordinal);
        var declared = hashers.SelectMany(hasher =>
            IdsOf(hasher).OfType<string>().Where(PhcString.IsName).Select(id => (Hasher: hasher, Id: id)));

        foreach (var (hasher, id) in declared)
        {
            if (!byId.TryAdd(id, hasher))
                failures.Add(DuplicateId(id, byId[id], hasher));
        }

        return failures.Count > 0 ? throw new ZeeKayDaConfigurationException([.. failures]) : byId;
    }

    private static readonly Func<IClientSecretHasher, ZeeKayDaConfigurationFailure?>[] DeclarationRules =
    [
        hasher => hasher.AlgorithmIds is { Count: > 0 }
            ? null
            : new ZeeKayDaConfigurationFailure(
                "configuration.hashers.no_algorithm_ids",
                $"The IClientSecretHasher '{hasher.GetType().FullName}' declares no AlgorithmIds, so no " +
                "stored secret can ever reach it."),
        hasher => IdsOf(hasher).All(PhcString.IsName)
            ? null
            : new ZeeKayDaConfigurationFailure(
                "configuration.hashers.invalid_algorithm_id",
                $"The IClientSecretHasher '{hasher.GetType().FullName}' declares an algorithm id that " +
                "is not 1–32 characters from [a-z0-9-]."),
    ];

    private static IEnumerable<string?> IdsOf(IClientSecretHasher hasher) =>
        (IEnumerable<string?>?)hasher.AlgorithmIds ?? [];

    private static ZeeKayDaConfigurationFailure DuplicateId(
        string id, IClientSecretHasher first, IClientSecretHasher second) =>
        new(
            "configuration.hashers.duplicate_algorithm_id",
            $"The algorithm id '{id}' is declared by both '{first.GetType().FullName}' and " +
            $"'{second.GetType().FullName}'. Each id must belong to exactly one registered hasher.");

    private static ClientSecret CreateTimingDecoy(
        IReadOnlyDictionary<string, IClientSecretHasher> hashersById, IClientSecretHasher hasher)
    {
        ClientSecret? decoy;
        try
        {
            decoy = hasher.CreateTimingDecoy();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never ex.Message: it is the hasher's text, and failure messages are logged verbatim.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.timing_decoy_unhandled",
                    $"The IClientSecretHasher '{hasher.GetType().FullName}' threw {ex.GetType().FullName} " +
                    "building its timing decoy. Every registered hasher's Create runs once at startup, " +
                    "a verify-only hasher included, so it must succeed for a random value."),
                ex);
        }

        if (IsOwnOutput(hashersById, hasher, decoy))
            return decoy!;

        // Error codes below are stable API — do not rename without a semver-major bump.
        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "configuration.hashers.timing_decoy_unhandled",
                $"The IClientSecretHasher '{hasher.GetType().FullName}' returned no timing decoy, " +
                "or one whose algorithm id is not among its own AlgorithmIds. For a hasher that does not " +
                "build its own decoy, the decoy is what its Create returns for a random value. Failure-path " +
                "timing padding verifies against that decoy, and one the hasher does not own would make " +
                "every padding verification return at once, which would reopen the timing oracle."));
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

        var markedDefaults = options.Registrations.Count(r => r.IsDefault);
        if (markedDefaults > 1)
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "configuration.hashers.multiple_defaults",
                    $"{markedDefaults} IClientSecretHasher implementations are marked as default. " +
                    "At most one hasher may have isDefault: true; with none, PBKDF2 is the default."));

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
