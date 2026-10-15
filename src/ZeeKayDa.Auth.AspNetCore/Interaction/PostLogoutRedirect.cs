using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Where a sign-out sends the user back to, and the client's <c>state</c> to echo there.
/// </summary>
/// <remarks>
/// <see cref="For"/>, the registration match, is the only way to make one.
/// </remarks>
internal sealed class PostLogoutRedirect
{
    private PostLogoutRedirect(string uri, string? state)
    {
        Uri = uri;
        State = state;
    }

    /// <summary>The registered URI to send the user to.</summary>
    public string Uri { get; }

    /// <summary>The client's <c>state</c>, echoed there, or <see langword="null"/>.</summary>
    public string? State { get; }

    /// <summary>
    /// The redirect for <paramref name="postLogoutRedirectUri"/> when the client registered it
    /// exactly (ordinal), else <see langword="null"/>.
    /// </summary>
    public static PostLogoutRedirect? For(IClient? client, string? postLogoutRedirectUri, string? state) =>
        client is not null
        && postLogoutRedirectUri is not null
        && client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri, StringComparer.Ordinal)
            ? new PostLogoutRedirect(postLogoutRedirectUri, state)
            : null;
}
