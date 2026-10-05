namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What the host's login page renders for: the client the user is signing in to, the ways they
/// can sign in, and how their last trip to an external provider ended, if it did not sign them
/// in. Read through <see cref="LoginInteraction.GetRequestAsync"/>.
/// </summary>
public sealed class LoginRequest
{
    internal LoginRequest(
        ClientInformation client,
        IReadOnlyList<ProviderDescriptor> providers,
        bool localLoginEnabled,
        ProviderReturn? providerReturn)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(providers);

        Client = client;
        Providers = providers;
        LocalLoginEnabled = localLoginEnabled;
        ProviderReturn = providerReturn;
    }

    /// <summary>The client the user is signing in to.</summary>
    public ClientInformation Client { get; }

    /// <summary>
    /// The external providers the host registered through <c>WithProviders</c>, in registration
    /// order, for the page to render as a choice; empty when none are registered. A
    /// <see cref="ProviderDescriptor.Id"/> is handed back to
    /// <see cref="LoginInteraction.ChallengeAsync"/> to select that provider, never written by the
    /// page.
    /// </summary>
    public IReadOnlyList<ProviderDescriptor> Providers { get; }

    /// <summary>
    /// Whether the page should render a credential form of its own — the value of
    /// <c>AuthorizationEndpoint.Interaction.SupportsLocalSignIn</c>.
    /// </summary>
    public bool LocalLoginEnabled { get; }

    /// <summary>
    /// How the user's last trip to an external provider ended when it brought them back here
    /// instead of signing them in, or <see langword="null"/> on an ordinary arrival from the
    /// authorization endpoint. Cleared when the user picks a provider again.
    /// </summary>
    public ProviderReturn? ProviderReturn { get; }
}
