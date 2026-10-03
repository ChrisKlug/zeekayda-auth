using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

// Whether the client is public or confidential, how it authenticates at the token endpoint, and
// the secrets it authenticates with.
internal sealed partial class ClientRegistrationValidator
{
    /// <summary>
    /// The rules for one secret, in order; the first that finds anything reports it and the rest do
    /// not run.
    /// </summary>
    private static readonly Func<SecretCheck, IReadOnlyList<ZeeKayDaConfigurationFailure>>[] SecretRules =
    [
        HasNoValue,
        IsMalformed,
        HasNoHasher,
        IsRefusedByItsHasher,
    ];

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateCredentials(IClientWithCredentials client) =>
        ValidateIsPublicTrinity(client)
            .Concat(ValidateAuthMethods(client))
            .Concat(ValidatePkceOptOut(client))
            .Concat(ValidateSecrets(client));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIsPublicTrinity(IClientWithCredentials client)
    {
        var hasNoSecrets = client.Secrets.Count == 0;

        // Enumerate with explicit ordinal comparison — do NOT trust the set's comparer or its
        // Count: a custom set can report one entry while yielding 'none' and another method.
        var authMethodCount = 0;
        var hasNoneMethod = false;

        foreach (var method in client.AllowedTokenEndpointAuthMethods)
        {
            authMethodCount++;
            if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
                hasNoneMethod = true;
        }

        var authMethodsIsNoneOnly = authMethodCount == 1 && hasNoneMethod;

        if (!client.IsPublic && authMethodCount == 0)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.empty",
                $"Client '{client.ClientId}' is confidential (IsPublic=false) but AllowedTokenEndpointAuthMethods is empty. " +
                "Confidential clients must specify at least one token endpoint authentication method.");
        }

        if (client.IsPublic != hasNoSecrets || client.IsPublic != authMethodsIsNoneOnly)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.is_public.trinity_violation",
                $"Client '{client.ClientId}' has inconsistent public/confidential configuration. " +
                $"IsPublic={client.IsPublic}, Secrets.Count={client.Secrets.Count}, " +
                $"AllowedTokenEndpointAuthMethods=[{string.Join(", ", client.AllowedTokenEndpointAuthMethods)}]. " +
                "The three-way consistency rule requires: IsPublic=true ⟺ Secrets.Count=0 ⟺ AllowedTokenEndpointAuthMethods={\"none\"}.");
        }
    }

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateAuthMethods(IClientWithCredentials client)
    {
        // The trinity only rejects a "none-only" confidential client, so a mixed set like
        // {"none","client_secret_basic"} would otherwise let it be called without credentials.
        if (!client.IsPublic && TokenEndpointAuthMethodRules.AllowsNone(client.AllowedTokenEndpointAuthMethods))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.none_on_confidential",
                $"Confidential client '{client.ClientId}' has 'none' in AllowedTokenEndpointAuthMethods. " +
                "The 'none' method is only valid for public clients (RFC 6749 §2.3).");
        }

        var serverMethods = new HashSet<string>(options.Value.TokenEndpoint.AuthMethodsSupported, StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var method in client.AllowedTokenEndpointAuthMethods)
        {
            if (ValidateAuthMethod(client, method, seen, serverMethods) is { } failure)
                yield return failure;
        }
    }

    /// <summary>
    /// The entry's first broken rule, if any: a malformed entry is not also a duplicate, and a
    /// duplicate is not also checked against the server's methods.
    /// </summary>
    private static ZeeKayDaConfigurationFailure? ValidateAuthMethod(
        IClientWithCredentials client,
        string? method,
        HashSet<string> seen,
        HashSet<string> serverMethods)
    {
        if (!TokenEndpointAuthMethodRules.IsWellFormed(method))
        {
            return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.invalid_entry",
                $"Client '{client.ClientId}' has an invalid entry in AllowedTokenEndpointAuthMethods: " +
                $"'{method}'. Entries must be non-null, non-empty, have no leading/trailing whitespace, " +
                "and contain no control characters.");
        }

        if (!seen.Add(method))
        {
            return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.duplicate",
                $"Client '{client.ClientId}' has a duplicate entry in AllowedTokenEndpointAuthMethods: '{method}'.");
        }

        return serverMethods.Contains(method) ? null : AuthMethodNotSupportedByServer(client, method, serverMethods);
    }

    // 'none' outside the server's methods on a public client is a host that registered one without
    // opting in to accepting them — the common first-run mistake — so its failure names the opt-in.
    // A confidential client listing 'none' is fixed by removing it (none_on_confidential), never by
    // advertising it, so it gets no hint.
    private static ZeeKayDaConfigurationFailure AuthMethodNotSupportedByServer(
        IClientWithCredentials client,
        string method,
        HashSet<string> serverMethods)
    {
        var needsNoneOptIn = client.IsPublic && string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal);
        var fix = needsNoneOptIn
            ? " Public clients present no credentials at the token endpoint, so the server accepts them " +
              "only when it advertises 'none': add " +
              "options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None); to the " +
              "AddZeeKayDaAuth configuration, or 'none' to TokenEndpoint:AuthMethodsSupported in bound configuration."
            : "";

        return new ZeeKayDaConfigurationFailure(
            "client.token_endpoint_auth_methods.not_subset",
            $"Client '{client.ClientId}' has AllowedTokenEndpointAuthMethods entry '{method}' that is not " +
            $"in the server's AuthMethodsSupported: [{string.Join(", ", serverMethods)}]." + fix);
    }

    /// <summary>
    /// A public client has no credential, so PKCE is its only proof that the party redeeming the
    /// code is the one that started the flow; nothing else can stand in for it.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidatePkceOptOut(IClientWithCredentials client)
    {
        if (client.IsPublic && !client.RequirePkce)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.require_pkce.disabled_on_public",
                $"Public client '{client.ClientId}' has RequirePkce set to false. " +
                "A public client must always use PKCE (OAuth 2.1 §7.5.1.1, RFC 9700 §2.1.1); " +
                "only a confidential client may be registered without it.");
        }
    }

    /// <summary>
    /// One bad secret refuses the whole client, even when its other secret is fine: skipping it
    /// would hide a broken rotation until the good secret is retired. No message the framework
    /// writes contains a stored value, beyond the well-formed algorithm id
    /// <c>client.credentials.no_hasher</c> names.
    /// </summary>
    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateSecrets(IClientWithCredentials client)
    {
        // Counted by enumerating, never from Count: a store's own list can report fewer entries than
        // it yields, and the cap bounds the timing work of every failed authentication.
        var count = 0;
        foreach (var secret in client.Secrets)
        {
            count++;
            var check = new SecretCheck(client.ClientId, secret, registry);
            foreach (var failure in SecretRules.Select(rule => rule(check)).FirstOrDefault(found => found.Count > 0) ?? [])
                yield return failure;
        }

        if (count > ClientSecrets.MaxActiveSecretsPerClient)
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.credentials.too_many_secrets",
                $"Client '{client.ClientId}' has {count} secrets, which exceeds the " +
                $"maximum of {ClientSecrets.MaxActiveSecretsPerClient}. " +
                "The two-secret cap exists to support rotation while preserving timing-oracle defences.");
        }
    }

    private sealed record SecretCheck(string ClientId, ClientSecret? Secret, ClientSecretHasherRegistry Registry)
    {
        // Every rule after HasNoValue runs only once it found a value.
        public ClientSecret Stored => Secret!;
    }

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> HasNoValue(SecretCheck check) =>
        string.IsNullOrEmpty(check.Secret?.Value)
            ?
            [
                new(
                    "client.credentials.null_entry",
                    $"Client '{check.ClientId}' has a null entry in Secrets, or one with no Value. It can never be " +
                    "verified; remove it."),
            ]
            : [];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> IsMalformed(SecretCheck check) =>
        ClientSecretHasherRegistry.AlgorithmIdOf(check.Stored.Value) is null
            ?
            [
                new(
                    "client.credentials.malformed_secret",
                    $"Client '{check.ClientId}' has a secret that does not start with $<algorithm id>$, an id of " +
                    "1–32 characters from [a-z0-9-]. A stored secret is a hash such as $pbkdf2-sha256$..., never " +
                    "the plaintext; create one with IClientSecrets."),
            ]
            : [];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> HasNoHasher(SecretCheck check) =>
        check.Registry.CanVerify(check.Stored)
            ? []
            :
            [
                new(
                    "client.credentials.no_hasher",
                    $"Client '{check.ClientId}' has a secret with algorithm id " +
                    $"'{ClientSecretHasherRegistry.AlgorithmIdOf(check.Stored.Value)}', which no registered " +
                    "IClientSecretHasher declares. The secret can never be verified."),
            ];

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> IsRefusedByItsHasher(SecretCheck check) =>
        check.Registry.ValidateStoredSecret(check.Stored, check.ClientId);
}
