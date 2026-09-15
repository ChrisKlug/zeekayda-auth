using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Where a sign-out sends the user back to: a post-logout redirect URI the client registered, and
/// the client's <c>state</c> to echo there.
/// </summary>
/// <remarks>
/// There is no public constructor, so an instance cannot exist for a URI no registration vouches
/// for: <see cref="For"/> is the only way to make one, and it is the match.
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
    /// The redirect for <paramref name="postLogoutRedirectUri"/>, or <see langword="null"/> when
    /// there is no client to vouch for it, none was asked for, or the one asked for is not among
    /// the client's registered URIs by exact ordinal comparison.
    /// </summary>
    public static PostLogoutRedirect? For(IClientMetadata? client, string? postLogoutRedirectUri, string? state) =>
        client is not null
        && postLogoutRedirectUri is not null
        && client.PostLogoutRedirectUris.Contains(postLogoutRedirectUri, StringComparer.Ordinal)
            ? new PostLogoutRedirect(postLogoutRedirectUri, state)
            : null;
}
