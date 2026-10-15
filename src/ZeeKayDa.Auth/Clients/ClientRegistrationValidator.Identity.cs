using System.Text.RegularExpressions;

namespace ZeeKayDa.Auth.Clients;

// Who the client is: its client_id, and the name users are shown.
internal sealed partial class ClientRegistrationValidator
{
    private static readonly Regex ClientIdPattern =
        new(@"^[A-Za-z0-9_\-.]+$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateIdentity(IClientWithCredentials client)
    {
        if (!IsValidClientId(client.ClientId))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.client_id.invalid",
                $"Client has an invalid ClientId: '{client.ClientId}'. " +
                "ClientId must match [A-Za-z0-9_\\-.]+, be non-empty, and be at most 200 characters.");
        }

        // A display name is shown to users on the host's pages, so it is either absent or a
        // printable, bounded string — never something a page has to defend itself against.
        if (client.DisplayName is { } displayName && !IsValidDisplayName(displayName))
        {
            yield return new ZeeKayDaConfigurationFailure(
                "client.display_name.invalid",
                $"Client '{client.ClientId}' has an invalid DisplayName. " +
                "DisplayName must be null or a non-blank string of at most 200 characters with no control characters.");
        }
    }

    /// <summary>Non-empty, at most 200 characters, and only <c>[A-Za-z0-9_\-.]</c>.</summary>
    internal static bool IsValidClientId(string? clientId) =>
        !string.IsNullOrEmpty(clientId)
        && clientId.Length <= 200
        && ClientIdPattern.IsMatch(clientId);

    private static bool IsValidDisplayName(string displayName) =>
        !string.IsNullOrWhiteSpace(displayName)
        && displayName.Length <= 200
        && !displayName.Any(char.IsControl);
}
