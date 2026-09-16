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
    /// The client that sent the user here to sign out, for the page to name it; or
    /// <see langword="null"/> when the request named no registered client — a sign-out the user
    /// started by visiting the endpoint directly, for instance.
    /// </summary>
    public ClientInformation? Client { get; }

    /// <summary>
    /// The subject identifier of the user being signed out, as the host's sign-in supplied it, for
    /// the page to name them.
    /// </summary>
    /// <remarks>
    /// The user who was signed in when the sign-out was started, which is the only session it may
    /// end: <see cref="ILogoutInteraction.SignOutAsync"/> refuses if the browser is no longer
    /// carrying that session, so this never names one user and signs out another.
    /// </remarks>
    public string Subject { get; }
}
