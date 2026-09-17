namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>What kind of error the host's error page is being asked to render.</summary>
public enum AuthorizationErrorKind
{
    /// <summary>
    /// An authorization request was rejected and could not be sent back to the client — an unknown
    /// client or an unregistered redirect URI, where redirecting would be unsafe.
    /// </summary>
    RequestRejected,

    /// <summary>
    /// A login, consent or logout page was submitted with no live interaction behind it: it
    /// expired, was already completed, was started in another browser, or the page was reached
    /// directly. The user can only start again from the application.
    /// </summary>
    NothingToContinue,
}
