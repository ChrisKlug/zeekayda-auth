namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How the host takes part in an external provider sign-in. Configured through the second
/// argument of <c>WithProviders</c>.
/// </summary>
public sealed class ProviderOptions
{
    /// <summary>
    /// Gets or sets the handler that runs when a provider has authenticated the user, before the
    /// SSO session is established. <see langword="null"/> (the default) promotes the principal as it is.
    /// </summary>
    /// <remarks>
    /// The handler may end the request with <see cref="ProviderSignInContext.RedirectToAsync"/>,
    /// sending the user to a host page that finishes through <see cref="ProviderSignInInteraction"/>,
    /// or with <see cref="ProviderSignInContext.DenyAsync"/>. Calling neither promotes the principal.
    /// </remarks>
    public Func<ProviderSignInContext, Task>? OnProviderSignIn { get; set; }
}
