using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The registered hashers, checked and indexed by algorithm id at startup: which owns a stored secret,
/// which creates new ones, and each one's timing decoy, built here.
/// </summary>
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
    /// The text between a stored value's first two <c>$</c> when it is a valid id, else <see langword="null"/>;
    /// only an id this returns is ever logged.
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
    /// Whether <paramref name="hasher"/> owns <paramref name="secret"/>'s id, by the ids indexed at startup,
    /// never the hasher's live set.
    /// </summary>
    public bool IsHasherFor(IClientSecretHasher hasher, ClientSecret? secret) =>
        ReferenceEquals(HasherFor(secret), hasher);

    /// <summary>Whether a registered hasher declared the stored value's algorithm id.</summary>
    public bool CanVerify(ClientSecret stored) => HasherFor(stored) is not null;

    /// <summary>
    /// The owning hasher's failures for a stored secret, prefixed with the client id; a throw is reported by
    /// type, and an unowned secret is the validator's to report.
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
