using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The registered <see cref="IClientSecretHasher"/> implementations, checked and indexed by algorithm
/// id once, at startup: which hasher owns a stored secret, which one creates new secrets, and the
/// decoy each one verifies against when a failed authentication is padded.
/// </summary>
/// <remarks>
/// Every hasher's decoy is built in the constructor; see <see cref="IClientSecretHasher.CreateTimingDecoy"/>
/// for what that costs. Also holds the per-secret checks a client registration runs, since they
/// dispatch to the same hashers and never pad.
/// </remarks>
internal sealed class ClientSecretHasherRegistry
{
    private readonly IReadOnlyDictionary<string, IClientSecretHasher> _hashersById;

    public ClientSecretHasherRegistry(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherRegistrationOptions> registrationOptions)
    {
        var hasherList = hashers.ToList();
        Default = ResolveDefault(hasherList, registrationOptions.Value);
        _hashersById = IndexByAlgorithmId(hasherList);
        TimingDecoys = hasherList.Select(hasher => (hasher, CreateTimingDecoy(hasher))).ToList().AsReadOnly();
    }

    /// <summary>The hasher that creates new secrets.</summary>
    public IClientSecretHasher Default { get; }

    /// <summary>Every registered hasher, with the stored secret padding verifies against.</summary>
    public IReadOnlyList<(IClientSecretHasher Hasher, ClientSecret Decoy)> TimingDecoys { get; }

    /// <summary>
    /// The algorithm id of a stored value: the text between its first two <c>$</c>, or
    /// <see langword="null"/> when the value does not start with <c>$&lt;id&gt;$</c> or that text could
    /// not be an id. Only an id this returns is ever written to a log.
    /// </summary>
    public static string? AlgorithmIdOf(string? value)
    {
        if (value is null || !value.StartsWith('$'))
            return null;

        var end = value.IndexOf('$', 1);
        return end > 1 && value[1..end] is var id && PhcString.IsName(id) ? id : null;
    }

    /// <summary>The hasher that declared the stored secret's algorithm id, if any.</summary>
    public IClientSecretHasher? HasherFor(ClientSecret? stored) =>
        AlgorithmIdOf(stored?.Value) is { } id ? _hashersById.GetValueOrDefault(id) : null;

    /// <summary>
    /// Whether <paramref name="hasher"/> is the one that owns <paramref name="secret"/>'s algorithm id.
    /// </summary>
    /// <remarks>
    /// Checked against the ids indexed at startup, never the hasher's live AlgorithmIds: a set that
    /// changed since would let through a secret dispatch can never route back to this hasher.
    /// </remarks>
    public bool IsHasherFor(IClientSecretHasher hasher, ClientSecret? secret) =>
        ReferenceEquals(HasherFor(secret), hasher);

    /// <summary>Whether a registered hasher declared the stored value's algorithm id.</summary>
    public bool CanVerify(ClientSecret stored) => HasherFor(stored) is not null;

    /// <summary>
    /// The owning hasher's failures for a stored secret, each prefixed with the client id. A hasher
    /// that throws is reported by exception type. A secret no hasher declared yields nothing here:
    /// the validator reports <c>client.credentials.no_hasher</c> for it.
    /// </summary>
    public IReadOnlyList<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored, string clientId)
    {
        var owner = HasherFor(stored);
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

    private ClientSecret CreateTimingDecoy(IClientSecretHasher hasher)
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

        if (IsHasherFor(hasher, decoy))
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
