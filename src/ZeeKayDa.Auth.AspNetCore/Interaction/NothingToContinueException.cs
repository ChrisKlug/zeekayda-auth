namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A page was submitted, or read, for an interaction this browser no longer has; a terminal call
/// answers it, a read lets it reach the host.
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
    /// The request carries no <c>zkd_i</c>: a bookmark, or a host form that drops it.
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
