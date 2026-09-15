using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates how a client authenticates at the token endpoint — its
/// <see cref="IClientMetadata.AllowedTokenEndpointAuthMethods"/>, and their consistency with
/// <see cref="IClientMetadata.IsPublic"/> and its credentials — and records a
/// <see cref="ZeeKayDaConfigurationFailure"/> for every rule it breaks.
/// </summary>
internal static class TokenEndpointAuthMethodValidator
{
    /// <summary>
    /// Validates the client's allowed methods against the server's supported methods.
    /// </summary>
    internal static void Validate(
        IClientRegistration client,
        IReadOnlySet<string> serverMethods,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        ValidateIsPublicTrinity(client, failures);

        // A confidential client must never advertise 'none' as a valid auth method: doing so would
        // allow it to be called without credentials. The trinity check only rejects a "none-only"
        // confidential client, so a mixed set like {"none","client_secret_basic"} slips past it.
        if (!client.IsPublic && TokenEndpointAuthMethodRules.AllowsNone(client.AllowedTokenEndpointAuthMethods))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.none_on_confidential",
                $"Confidential client '{client.ClientId}' has 'none' in AllowedTokenEndpointAuthMethods. " +
                "The 'none' method is only valid for public clients (RFC 6749 §2.3)."));
        }

        // A plain loop, not Select: ValidateEntry records each entry in 'seen', and a deferred
        // sequence enumerated twice would report every valid entry as a duplicate.
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var method in client.AllowedTokenEndpointAuthMethods)
        {
            if (ValidateEntry(client.ClientId, method, seen, serverMethods) is { } failure)
                failures.Add(failure);
        }
    }

    private static void ValidateIsPublicTrinity(
        IClientRegistration client,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var hasNoCredentials = client.Credentials.Count == 0;

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

        // Check empty AllowedTokenEndpointAuthMethods for confidential clients explicitly
        if (!client.IsPublic && authMethodCount == 0)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.empty",
                $"Client '{client.ClientId}' is confidential (IsPublic=false) but AllowedTokenEndpointAuthMethods is empty. " +
                "Confidential clients must specify at least one token endpoint authentication method."));
        }

        // Three-way consistency check
        if (client.IsPublic != hasNoCredentials || client.IsPublic != authMethodsIsNoneOnly)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.is_public.trinity_violation",
                $"Client '{client.ClientId}' has inconsistent public/confidential configuration. " +
                $"IsPublic={client.IsPublic}, Credentials.Count={client.Credentials.Count}, " +
                $"AllowedTokenEndpointAuthMethods=[{string.Join(", ", client.AllowedTokenEndpointAuthMethods)}]. " +
                "The three-way consistency rule requires: IsPublic=true ⟺ Credentials.Count=0 ⟺ AllowedTokenEndpointAuthMethods={\"none\"}."));
        }
    }

    /// <summary>
    /// The entry's first broken rule, or <see langword="null"/> when it broke none: a malformed
    /// entry is not also a duplicate, and a duplicate is not also checked against the server's methods.
    /// </summary>
    private static ZeeKayDaConfigurationFailure? ValidateEntry(
        string clientId,
        string? method,
        HashSet<string> seen,
        IReadOnlySet<string> serverMethods)
    {
        if (!TokenEndpointAuthMethodRules.IsWellFormed(method))
        {
            return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.invalid_entry",
                $"Client '{clientId}' has an invalid entry in AllowedTokenEndpointAuthMethods: " +
                $"'{method}'. Entries must be non-null, non-empty, have no leading/trailing whitespace, " +
                "and contain no control characters.");
        }

        if (!seen.Add(method))
        {
            return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.duplicate",
                $"Client '{clientId}' has a duplicate entry in AllowedTokenEndpointAuthMethods: '{method}'.");
        }

        if (!serverMethods.Contains(method))
            return NotSupportedByServer(clientId, method, serverMethods);

        return null;
    }

    // 'none' outside the server's methods is a host that registered a public client without opting
    // in to accepting them — the common first-run mistake — so its failure names the opt-in.
    private static ZeeKayDaConfigurationFailure NotSupportedByServer(
        string clientId,
        string method,
        IReadOnlySet<string> serverMethods)
    {
        var fix = string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal)
            ? " Public clients present no credentials at the token endpoint, so the server accepts them " +
              "only when it advertises 'none': add " +
              "options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None) to the " +
              "AddZeeKayDaAuth configuration, or 'none' to TokenEndpoint:AuthMethodsSupported in bound configuration."
            : "";

        return new ZeeKayDaConfigurationFailure(
            "client.token_endpoint_auth_methods.not_subset",
            $"Client '{clientId}' has AllowedTokenEndpointAuthMethods entry '{method}' that is not " +
            $"in the server's AuthMethodsSupported: [{string.Join(", ", serverMethods)}]." + fix);
    }
}
