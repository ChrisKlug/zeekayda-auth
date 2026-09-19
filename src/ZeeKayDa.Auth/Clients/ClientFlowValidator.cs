using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates the flows a client may use — its <see cref="IClientMetadata.AllowedGrantTypes"/>,
/// <see cref="IClientMetadata.AllowedResponseTypes"/> and <see cref="IClientMetadata.AllowedResponseModes"/>
/// — against what the server serves, and records a <see cref="ZeeKayDaConfigurationFailure"/> for
/// every rule they break.
/// </summary>
/// <remarks>
/// A client is allowed only what the server serves. A value outside the server's set starts fine
/// and then silently does nothing, and an empty set refuses every request without saying why; both
/// are misconfigurations the operator should see at startup, not diagnose from a refusal.
/// </remarks>
internal static class ClientFlowValidator
{
    /// <summary>
    /// Validates the client's three flow sets against the server's supported values.
    /// </summary>
    internal static void Validate(
        IClientRegistration client,
        AuthorizationServerOptions options,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var grantTypes = new FlowSet<GrantType>(
            nameof(IClientMetadata.AllowedGrantTypes), client.AllowedGrantTypes,
            nameof(AuthorizationServerOptions.GrantTypesSupported), options.GrantTypesSupported,
            "client.grant_types");
        var responseTypes = new FlowSet<ResponseType>(
            nameof(IClientMetadata.AllowedResponseTypes), client.AllowedResponseTypes,
            "Response.TypesSupported", options.Response.TypesSupported,
            "client.response_types");
        var responseModes = new FlowSet<ResponseMode>(
            nameof(IClientMetadata.AllowedResponseModes), client.AllowedResponseModes,
            "Response.ModesSupported", options.Response.ModesSupported,
            "client.response_modes");

        if (ValidateEntries(client, grantTypes, failures) == 0)
            failures.Add(Empty(client, grantTypes, ", so it can use no grant"));

        var responseTypeCount = ValidateEntries(client, responseTypes, failures);
        var responseModeCount = ValidateEntries(client, responseModes, failures);

        // Only the code grant goes through the authorization endpoint, so only a client allowed it
        // needs a response type and mode to be answered with there. RFC 7591 §2.1 pairs that grant
        // with the code response type and gives every other grant none; a response mode only shapes
        // the authorization response, so it follows the same rule. Enumerated, not Contains: a
        // custom registration's set may answer Contains differently from what it yields.
        if (!client.AllowedGrantTypes.Any(grantType => grantType == GrantType.AuthorizationCode))
            return;

        const string reason = " but allows the authorization_code grant, which the authorization endpoint cannot answer without one";

        if (responseTypeCount == 0)
            failures.Add(Empty(client, responseTypes, reason));

        if (responseModeCount == 0)
            failures.Add(Empty(client, responseModes, reason));
    }

    /// <summary>
    /// Records every entry's first broken rule and returns how many entries the set yielded —
    /// counted by enumerating, because a custom registration's set may report a different
    /// <c>Count</c> from what it yields.
    /// </summary>
    private static int ValidateEntries<T>(
        IClientRegistration client,
        FlowSet<T> set,
        List<ZeeKayDaConfigurationFailure> failures)
        where T : struct, Enum
    {
        var count = 0;

        foreach (var value in set.Values)
        {
            count++;
            if (ValidateEntry(client, set, value) is { } failure)
                failures.Add(failure);
        }

        return count;
    }

    /// <summary>
    /// The entry's first broken rule, or <see langword="null"/> when it broke none: an undefined
    /// value is not also reported as one the server does not serve.
    /// </summary>
    private static ZeeKayDaConfigurationFailure? ValidateEntry<T>(
        IClientRegistration client,
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

    private static ZeeKayDaConfigurationFailure Empty<T>(
        IClientRegistration client,
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
}
