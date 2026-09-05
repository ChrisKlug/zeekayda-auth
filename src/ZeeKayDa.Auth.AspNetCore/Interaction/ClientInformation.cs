namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The client an authorization request is being completed for, as a host page sees it.
/// </summary>
public sealed class ClientInformation
{
    internal ClientInformation(string clientId, string? displayName)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        ClientId = clientId;
        DisplayName = displayName;
    }

    /// <summary>The identifier of the registered client that sent the authorization request.</summary>
    public string ClientId { get; }

    /// <summary>
    /// The registration's display name, for showing the user which application is asking, or
    /// <see langword="null"/> when the registration carries none — show <see cref="ClientId"/>
    /// then.
    /// </summary>
    public string? DisplayName { get; }
}
