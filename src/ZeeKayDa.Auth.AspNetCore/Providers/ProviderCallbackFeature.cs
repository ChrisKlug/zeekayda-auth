namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Set on the request by a provider's callback endpoint after routing and before the handler
/// runs: which provider the request is for — decided by the route, never by anything the handler
/// or the request says — and whether the provider reported that the user refused.
/// </summary>
internal sealed class ProviderCallbackFeature
{
    public ProviderCallbackFeature(ProviderRegistration provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        Provider = provider;
    }

    public void MarkRefused(string? interactionId)
    {
        Refused = true;
        RefusedInteractionId = interactionId;
    }

    public ProviderRegistration Provider { get; }

    /// <summary>Whether the provider reported a refusal by the user.</summary>
    public bool Refused { get; private set; }

    /// <summary>
    /// The interaction the refused challenge was issued for, read from the properties the handler
    /// unprotected, or <see langword="null"/> when they did not carry one.
    /// </summary>
    public string? RefusedInteractionId { get; private set; }
}
