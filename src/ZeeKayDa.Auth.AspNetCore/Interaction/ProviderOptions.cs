namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How the host takes part in an external provider sign-in. Configured through the second
/// argument of <c>WithProviders</c>.
/// </summary>
public sealed class ProviderOptions
{
    /// <summary>
    /// Gets or sets the handler that runs when a provider has authenticated the user and the
    /// framework is about to establish the SSO session. <see langword="null"/> (the default)
    /// promotes the provider's principal as it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The handler may end the request in one of two ways, each terminal:
    /// <see cref="ProviderSignInContext.RedirectToAsync"/> parks the principal and sends the user
    /// to a host page — to link the external identity to a local account, or to collect what the
    /// provider did not supply — and <see cref="ProviderSignInContext.DenyAsync"/> refuses the
    /// sign-in. A handler that calls neither lets the framework promote the principal; a host
    /// with nothing to collect writes no handler at all.
    /// </para>
    /// <para>
    /// The page a redirect leads to reads the parked principal with
    /// <see cref="ILoginInteraction.GetPendingPrincipalAsync"/> and finishes with
    /// <see cref="ILoginInteraction.SignInAsync"/>, passing the principal it wants the session
    /// to hold.
    /// </para>
    /// </remarks>
    public Func<ProviderSignInContext, Task>? OnProviderSignIn { get; set; }
}
