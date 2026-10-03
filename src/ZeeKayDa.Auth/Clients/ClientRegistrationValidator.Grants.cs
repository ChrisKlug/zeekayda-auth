using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Clients;

// What the client may do: its grants, response types and modes, scopes, and prompt values.
//
// A client is allowed only what the server serves. A value outside the server's set starts fine and
// then silently does nothing, and an empty set refuses every request without saying why; both are
// misconfigurations the operator should see at startup, not diagnose from a refusal.
internal sealed partial class ClientRegistrationValidator
{
    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateGrants(IClientWithCredentials client) =>
        ValidateGrantTypes(client)
            .Concat(ValidateResponseFlows(client))
            .Concat(ValidateAllowedScopes(client))
            .Concat(ValidateAllowedPromptValues(client));

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateGrantTypes(IClientWithCredentials client)
    {
        var grantTypes = new FlowSet<GrantType>(
            nameof(IClient.AllowedGrantTypes), client.AllowedGrantTypes,
            nameof(AuthorizationServerOptions.GrantTypesSupported), options.Value.GrantTypesSupported,
            "client.grant_types");

        var (failures, count) = ValidateFlowEntries(client, grantTypes);
        if (count == 0)
            failures.Add(EmptyFlowSet(client, grantTypes, ", so it can use no grant"));

        // RFC 6749 §4.4: the client credentials grant MUST only be used by confidential clients.
        if (client.IsPublic && client.AllowedGrantTypes.Any(grantType => grantType == GrantType.ClientCredentials))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "client.grant_types.client_credentials_on_public",
                $"Client '{client.ClientId}' is public but allows the client_credentials grant, which only a " +
                "confidential client may use (RFC 6749 §4.4). Register it as confidential, or remove the grant."));
        }

        WarnOfRefreshWithoutIssuer(client);
        return failures;
    }

    /// <summary>
    /// Only warns: a client whose code grant was withdrawn may still be draining refresh tokens it
    /// was issued before. The code grant is the only one that issues them (RFC 6749 §4.4.3).
    /// </summary>
    private void WarnOfRefreshWithoutIssuer(IClientWithCredentials client)
    {
        var refreshWithoutIssuer = !AllowsCodeGrant(client)
            && client.AllowedGrantTypes.Any(grantType => grantType == GrantType.RefreshToken);

        if (refreshWithoutIssuer && FirstTime(client.ClientId, "refresh-without-issuer"))
        {
            logger.LogWarning(
                "Client '{ClientId}' allows the refresh_token grant but not authorization_code, the only grant " +
                "that issues a refresh token, so it can use only refresh tokens issued before.",
                client.ClientId);
        }
    }

    private IEnumerable<ZeeKayDaConfigurationFailure> ValidateResponseFlows(IClientWithCredentials client)
    {
        var server = options.Value;
        var responseTypes = new FlowSet<ResponseType>(
            nameof(IClient.AllowedResponseTypes), client.AllowedResponseTypes,
            "Response.TypesSupported", server.Response.TypesSupported,
            "client.response_types");
        var responseModes = new FlowSet<ResponseMode>(
            nameof(IClient.AllowedResponseModes), client.AllowedResponseModes,
            "Response.ModesSupported", server.Response.ModesSupported,
            "client.response_modes");

        var (failures, responseTypeCount) = ValidateFlowEntries(client, responseTypes);
        var (modeFailures, responseModeCount) = ValidateFlowEntries(client, responseModes);
        failures.AddRange(modeFailures);

        // Only the code grant goes through the authorization endpoint, so only a client allowed it
        // needs a response type and mode to be answered with there (RFC 7591 §2.1).
        if (!AllowsCodeGrant(client))
            return failures;

        const string reason = " but allows the authorization_code grant, which the authorization endpoint cannot answer without one";

        if (responseTypeCount == 0)
            failures.Add(EmptyFlowSet(client, responseTypes, reason));

        if (responseModeCount == 0)
            failures.Add(EmptyFlowSet(client, responseModes, reason));

        return failures;
    }

    // Enumerated, not Contains: a custom registration's set may answer Contains differently from
    // what it yields.
    private static bool AllowsCodeGrant(IClient client) =>
        client.AllowedGrantTypes.Any(grantType => grantType == GrantType.AuthorizationCode);

    /// <summary>
    /// Every entry's first broken rule, and how many entries the set yielded — counted by
    /// enumerating, because a custom registration's set may report a different <c>Count</c> from
    /// what it yields.
    /// </summary>
    private static (List<ZeeKayDaConfigurationFailure> Failures, int Count) ValidateFlowEntries<T>(
        IClientWithCredentials client,
        FlowSet<T> set)
        where T : struct, Enum
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();
        var count = 0;

        foreach (var value in set.Values)
        {
            count++;
            if (ValidateFlowEntry(client, set, value) is { } failure)
                failures.Add(failure);
        }

        return (failures, count);
    }

    /// <summary>
    /// The entry's first broken rule, or <see langword="null"/> when it broke none: an undefined
    /// value is not also reported as one the server does not serve.
    /// </summary>
    private static ZeeKayDaConfigurationFailure? ValidateFlowEntry<T>(
        IClientWithCredentials client,
        FlowSet<T> set,
        T value)
        where T : struct, Enum
    {
        if (!Enum.IsDefined(value))
        {
            return new ZeeKayDaConfigurationFailure(
                $"{set.CodePrefix}.undefined_value",
                $"Client '{client.ClientId}' has an undefined value '{value:D}' in {set.Property}.");
        }

        if (!set.Supported.Contains(value))
        {
            return new ZeeKayDaConfigurationFailure(
                $"{set.CodePrefix}.not_subset",
                $"Client '{client.ClientId}' has {set.Property} entry '{value}' that is not in the server's " +
                $"{set.ServerProperty}: [{string.Join(", ", set.Supported)}]. The server does not serve it, " +
                "so allowing it would do nothing.");
        }

        return null;
    }

    private static ZeeKayDaConfigurationFailure EmptyFlowSet<T>(
        IClientWithCredentials client,
        FlowSet<T> set,
        string reason)
        where T : struct, Enum =>
        new(
            $"{set.CodePrefix}.empty",
            $"Client '{client.ClientId}' has an empty {set.Property}{reason}. " +
            $"Add at least one of the server's {set.ServerProperty}: [{string.Join(", ", set.Supported)}].");

    /// <summary>
    /// One of the client's flow sets, the server's set it must stay inside, and the prefix of the
    /// failure codes it reports under.
    /// </summary>
    private sealed record FlowSet<T>(
        string Property,
        IEnumerable<T> Values,
        string ServerProperty,
        ICollection<T> Supported,
        string CodePrefix)
        where T : struct, Enum;

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateAllowedScopes(IClientWithCredentials client) =>
        client.AllowedScopes.Where(string.IsNullOrWhiteSpace).Select(_ => new ZeeKayDaConfigurationFailure(
            "client.allowed_scopes.blank_entry",
            $"Client '{client.ClientId}' has a null, empty, or whitespace-only entry in AllowedScopes. " +
            "Scope entries must be non-empty non-whitespace strings."));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateAllowedPromptValues(IClientWithCredentials client) =>
        client.AllowedPromptValues.Where(promptValue => !Enum.IsDefined(promptValue)).Select(promptValue => new ZeeKayDaConfigurationFailure(
            "client.prompt_values.undefined_value",
            $"Client '{client.ClientId}' has an undefined value '{(int)promptValue}' in AllowedPromptValues."));
}
