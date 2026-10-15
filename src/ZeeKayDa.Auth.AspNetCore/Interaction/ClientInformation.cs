namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The client an interaction is being completed for, as a host page sees it.
/// </summary>
public sealed class ClientInformation
{
    internal ClientInformation(string clientId, string? displayName)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        ClientId = clientId;
        DisplayName = displayName;
    }

    /// <summary>The identifier of the registered client that sent the request.</summary>
    public string ClientId { get; }

    /// <summary>
    /// The registration's display name, or <see langword="null"/>; show <see cref="ClientId"/> then.
    /// </summary>
    public string? DisplayName { get; }
}
