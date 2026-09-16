namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The sign-out the host's logout page is asked to confirm, as that page sees it.
/// </summary>
public sealed class LogoutRequest
{
    internal LogoutRequest(ClientInformation? client) => Client = client;

    /// <summary>
    /// The client that sent the user here to sign out, for the page to name it; or
    /// <see langword="null"/> when the request named no registered client — a sign-out the user
    /// started by visiting the endpoint directly, for instance.
    /// </summary>
    public ClientInformation? Client { get; }
}
