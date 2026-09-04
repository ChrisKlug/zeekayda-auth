namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The client an authorization request is being completed for, as a host page sees it.
/// </summary>
public sealed class ClientInformation
{
    internal ClientInformation(string clientId)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        ClientId = clientId;
    }

    /// <summary>The identifier of the registered client that sent the authorization request.</summary>
    public string ClientId { get; }
}
