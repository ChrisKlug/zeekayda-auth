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
    /// The subject identifier of the account being signed out, as the host's sign-in supplied it:
    /// the one the client's <c>id_token_hint</c> named, or else the account the client was last
    /// answered for.
    /// </summary>
    /// <remarks>
    /// The account <see cref="LogoutInteraction.SignOutAsync"/> ends. Both it and
    /// <see cref="LogoutInteraction.SignOutAllAsync"/> refuse once the browser no longer holds this
    /// account's session.
    /// </remarks>
    public string Subject { get; }

    /// <summary>
    /// Every account this browser is signed in to, <see cref="Subject"/> among them, the most
    /// recently used first: who <see cref="LogoutInteraction.SignOutAllAsync"/> signs out, for a page
    /// that offers it.
    /// </summary>
    public IReadOnlyList<SignedInAccount> SignedInAccounts { get; internal init; } = [];
}
