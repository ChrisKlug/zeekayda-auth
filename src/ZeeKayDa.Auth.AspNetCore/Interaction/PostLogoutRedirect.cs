namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Where a sign-out sends the user back to: a post-logout redirect URI already matched against
/// the client's registration, and the client's <c>state</c> to echo there.
/// </summary>
internal sealed record PostLogoutRedirect(string Uri, string? State);
