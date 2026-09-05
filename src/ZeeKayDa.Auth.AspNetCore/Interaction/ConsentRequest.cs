namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What the host's consent page asks the user: which client wants access, to what, on whose
/// behalf. Read through <see cref="IConsentInteraction.GetRequestAsync"/>.
/// </summary>
public sealed class ConsentRequest
{
    internal ConsentRequest(ClientInformation client, IReadOnlyList<string> scopes, string subject)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        Client = client;
        Scopes = scopes;
        Subject = subject;
    }

    /// <summary>The client asking for access.</summary>
    public ClientInformation Client { get; }

    /// <summary>
    /// The scopes being asked for — the requested scopes the client is allowed, in request order.
    /// What the page passes to <see cref="IConsentInteraction.GrantAsync"/> can only narrow this.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>
    /// The subject identifier of the signed-in user being asked, as the host's sign-in supplied
    /// it, for the page to show who is consenting.
    /// </summary>
    public string Subject { get; }
}
