namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Set on the request by a provider's callback endpoint after routing and before the handler
/// runs: which provider the request is for — decided by the route, never by anything the handler
/// or the request says — whether the provider reported that the user refused, and which
/// interaction a failed callback's challenge was issued for.
/// </summary>
internal sealed class ProviderCallbackFeature
{
    public ProviderCallbackFeature(ProviderRegistration provider, string? challengedInteractionId)
    {
        ArgumentNullException.ThrowIfNull(provider);

        Provider = provider;
        ChallengedInteractionId = challengedInteractionId;
    }

    public void MarkRefused(string? interactionId)
    {
        Refused = true;
        RefusedInteractionId = interactionId;
    }

    /// <summary>
    /// Records the interaction a failing callback's properties name, when the handler handed them
    /// over. A refusal recorded first keeps its own: the handler fails every refused callback.
    /// </summary>
    public void MarkFailed(string? interactionId) => FailedInteractionId ??= RefusedInteractionId ?? interactionId;

    public ProviderRegistration Provider { get; }

    /// <summary>Whether the provider reported a refusal by the user.</summary>
    public bool Refused { get; private set; }

    /// <summary>
    /// The interaction the refused challenge was issued for, read from the properties the handler
    /// unprotected after validating its correlation cookie. The only identifier a refusal may end
    /// an interaction at the client on.
    /// </summary>
    public string? RefusedInteractionId { get; private set; }

    /// <summary>The interaction a failing callback's properties named, when the handler handed them over.</summary>
    public string? FailedInteractionId { get; private set; }

    /// <summary>The interaction the request's one challenge cookie named, read when the callback arrived.</summary>
    public string? ChallengedInteractionId { get; }

    /// <summary>
    /// The interaction to return the user to the login page for: the handler's own properties first,
    /// which name exactly the challenge that failed, then the challenge cookie.
    /// </summary>
    public string? ReturnInteractionId => RefusedInteractionId ?? FailedInteractionId ?? ChallengedInteractionId;
}
