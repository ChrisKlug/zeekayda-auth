namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A page was submitted, or read, for an interaction this browser no longer has. Thrown inside the
/// framework and answered by <see cref="NothingToContinue"/> wherever a terminal call catches it;
/// a read that cannot answer it lets it reach the host as the
/// <see cref="ZeeKayDaInteractionException"/> it is.
/// </summary>
internal sealed class NothingToContinueException(NothingToContinueReason reason, string message)
    : ZeeKayDaInteractionException(message)
{
    /// <summary>Why there is nothing to continue.</summary>
    public NothingToContinueReason Reason { get; } = reason;
}

/// <summary>Why a page has nothing to continue.</summary>
internal enum NothingToContinueReason
{
    /// <summary>
    /// The request carries no <c>zkd_i</c> at all. A bookmarked page does this, but so does a host
    /// page whose form drops the parameter — the one reason that points at a bug.
    /// </summary>
    NoInteractionId,

    /// <summary>
    /// The request names an interaction this browser is not carrying: it expired, was already
    /// completed, or was started in another browser.
    /// </summary>
    NotFound,

    /// <summary>Another response completed the interaction, or it expired, while this one was being prepared.</summary>
    AlreadyCompleted,

    /// <summary>The session the interaction was for is no longer the one this browser holds.</summary>
    SessionChanged,

    /// <summary>The client the interaction is for is no longer registered, or no longer lists its redirect URI.</summary>
    ClientGone,

    /// <summary>The external sign-in parked for the interaction was already taken, or has expired.</summary>
    NothingParked,
}
