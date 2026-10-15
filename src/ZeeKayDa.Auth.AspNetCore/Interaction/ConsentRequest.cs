namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What the host's consent page asks the user, read through <see cref="ConsentInteraction.GetRequestAsync"/>.
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
    /// The requested scopes the client is allowed, in request order;
    /// <see cref="ConsentInteraction.GrantAsync"/> can only narrow them.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>
    /// The subject identifier of the user being asked, as the host's sign-in supplied it.
    /// </summary>
    public string Subject { get; }
}
