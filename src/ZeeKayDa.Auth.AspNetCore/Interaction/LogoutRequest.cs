namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The sign-out the host's logout page is asked to confirm, as that page sees it.
/// </summary>
public sealed class LogoutRequest
{
    internal LogoutRequest(ClientInformation? client, string subject)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        Client = client;
        Subject = subject;
    }

    /// <summary>
    /// The client that sent the user here to sign out, or <see langword="null"/> when the request
    /// named none, as when the user visited the endpoint directly.
    /// </summary>
    public ClientInformation? Client { get; }

    /// <summary>
    /// The subject identifier of the user being signed out, as the host's sign-in supplied it.
    /// </summary>
    /// <remarks>
    /// The only session the sign-out may end: <see cref="LogoutInteraction.SignOutAsync"/> refuses
    /// once the browser holds another.
    /// </remarks>
    public string Subject { get; }
}
