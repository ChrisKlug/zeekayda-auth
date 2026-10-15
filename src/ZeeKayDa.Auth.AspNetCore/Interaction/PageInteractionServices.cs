namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What every per-page interaction service needs to advance a request.
/// </summary>
internal sealed class PageInteractionServices(
    AuthorizationFlow flow,
    InteractionOutcomes outcomes,
    NothingToContinue nothingToContinue)
{
    /// <summary>The interaction state of the authorization request.</summary>
    public AuthorizationFlow Flow { get; } = flow;

    /// <summary>The ways an interaction step ends.</summary>
    public InteractionOutcomes Outcomes { get; } = outcomes;

    /// <summary>The answer to a page with nothing left to continue.</summary>
    public NothingToContinue NothingToContinue { get; } = nothingToContinue;
}

/// <summary>
/// The two response writers a nothing-to-continue answer picks between.
/// </summary>
internal sealed class InteractionAnswers(AuthorizationResponses authorization, EndSessionResponses endSession)
{
    /// <summary>How an authorization request is answered.</summary>
    public AuthorizationResponses Authorization { get; } = authorization;

    /// <summary>How a sign-out is answered.</summary>
    public EndSessionResponses EndSession { get; } = endSession;
}
