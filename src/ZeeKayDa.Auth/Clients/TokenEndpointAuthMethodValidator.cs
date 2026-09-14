using System.Diagnostics.CodeAnalysis;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Validates a client's <see cref="IClientMetadata.AllowedTokenEndpointAuthMethods"/> and records a
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
        // A confidential client must never advertise 'none' as a valid auth method: doing so would
        // allow it to be called without credentials. The trinity check only rejects a "none-only"
        // confidential client, so a mixed set like {"none","client_secret_basic"} slips past it.
        if (!client.IsPublic && AllowsNone(client.AllowedTokenEndpointAuthMethods))
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

    /// <summary>
    /// Whether the methods include <c>none</c>. Compares ordinally rather than trusting the set's
    /// own comparer, which a custom registration may have made case-insensitive.
    /// </summary>
    internal static bool AllowsNone(IEnumerable<string> methods)
        => methods.Any(method => string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal));

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
        if (!IsWellFormed(method))
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
        {
            return new ZeeKayDaConfigurationFailure(
                "client.token_endpoint_auth_methods.not_subset",
                $"Client '{clientId}' has AllowedTokenEndpointAuthMethods entry '{method}' that is not " +
                $"in the server's AuthMethodsSupported: [{string.Join(", ", serverMethods)}].");
        }

        return null;
    }

    /// <summary>Non-null, non-empty, no leading or trailing whitespace, and no control characters.</summary>
    private static bool IsWellFormed([NotNullWhen(true)] string? method)
        => !string.IsNullOrEmpty(method)
           && method == method.Trim()
           && !method.Any(char.IsControl);
}
