namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What every per-page interaction service needs to advance a request: the interaction state, the
/// outcomes that end it, and the answer for a page that has nothing left to continue. One
/// dependency rather than three, since no page service has ever wanted a subset.
/// </summary>
internal sealed class PageInteractionServices
{
    public PageInteractionServices(AuthorizationFlow flow, InteractionOutcomes outcomes, NothingToContinue nothingToContinue)
    {
        ArgumentNullException.ThrowIfNull(flow);
        ArgumentNullException.ThrowIfNull(outcomes);
        ArgumentNullException.ThrowIfNull(nothingToContinue);

        Flow = flow;
        Outcomes = outcomes;
        NothingToContinue = nothingToContinue;
    }

    /// <summary>The interaction state of the authorization request.</summary>
    public AuthorizationFlow Flow { get; }

    /// <summary>The ways an interaction step ends.</summary>
    public InteractionOutcomes Outcomes { get; }

    /// <summary>The answer to a page with nothing left to continue.</summary>
    public NothingToContinue NothingToContinue { get; }
}

/// <summary>
/// The two response writers a nothing-to-continue answer picks between: the authorization error
/// page and the signed-out page.
/// </summary>
internal sealed class InteractionAnswers
{
    public InteractionAnswers(AuthorizationResponses authorization, EndSessionResponses endSession)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(endSession);

        Authorization = authorization;
        EndSession = endSession;
    }

    /// <summary>How an authorization request is answered.</summary>
    public AuthorizationResponses Authorization { get; }

    /// <summary>How a sign-out is answered.</summary>
    public EndSessionResponses EndSession { get; }
}
