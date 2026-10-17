namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Set by a provider's callback endpoint before the handler runs: the provider, decided by the
/// route alone, whether the user refused, and the interaction a failed challenge was for.
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

    /// <summary>Records the interaction a failing callback's properties name; a refusal's, recorded first, stands.</summary>
    public void MarkFailed(string? interactionId)
    {
        Failed = true;
        FailedInteractionId ??= RefusedInteractionId ?? interactionId;
    }

    /// <summary>Records that the handler signed into the framework's external scheme.</summary>
    public void MarkSignedIn() => SignedIn = true;

    /// <summary>Whether the handler raised its failure event — whoever then answered the callback.</summary>
    public bool Failed { get; private set; }

    public ProviderRegistration Provider { get; }

    /// <summary>Whether the handler signed into the framework's external scheme.</summary>
    public bool SignedIn { get; private set; }

    /// <summary>Whether the handler reported handling its callback without either signing in or failing.</summary>
    public bool Abandoned => !SignedIn && !Failed && !Refused;

    /// <summary>Whether the provider reported a refusal by the user.</summary>
    public bool Refused { get; private set; }

    /// <summary>
    /// The refused challenge's interaction, from properties validated with the correlation cookie: the
    /// only identifier a refusal may end an interaction at the client on.
    /// </summary>
    public string? RefusedInteractionId { get; private set; }

    /// <summary>The interaction a failing callback's properties named, when the handler handed them over.</summary>
    public string? FailedInteractionId { get; private set; }

    /// <summary>The interaction the request's one challenge cookie named, read when the callback arrived.</summary>
    public string? ChallengedInteractionId { get; }

    /// <summary>The interaction to return to the login page for: the handler's properties first, then the cookie.</summary>
    public string? ReturnInteractionId => RefusedInteractionId ?? FailedInteractionId ?? ChallengedInteractionId;

    /// <summary>The interaction whose challenge failed, once the handler raised its failure event; otherwise <see langword="null"/>.</summary>
    public string? FailedChallengeInteractionId => Failed ? ReturnInteractionId : null;
}
