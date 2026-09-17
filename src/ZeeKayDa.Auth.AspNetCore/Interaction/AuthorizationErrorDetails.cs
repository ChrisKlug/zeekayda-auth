namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The details of an error that could not be sent back to the client, as surfaced to the host's
/// error page via <see cref="IErrorInteraction"/>.
/// </summary>
public sealed record AuthorizationErrorDetails
{
    /// <summary>
    /// What kind of error this is. A page that wants its own wording for an interaction the user
    /// can no longer continue checks for <see cref="AuthorizationErrorKind.NothingToContinue"/>.
    /// </summary>
    public required AuthorizationErrorKind Kind { get; init; }

    /// <summary>
    /// A machine-readable code: the OAuth 2.0 error code (RFC 6749 §4.1.2.1), e.g.
    /// <c>invalid_request</c>, for a rejected request, and <c>interaction_not_found</c> for an
    /// interaction there is nothing left of.
    /// </summary>
    public required string Error { get; init; }

    /// <summary>
    /// A generic human-readable description safe to render. Never contains request values.
    /// </summary>
    public required string Description { get; init; }
}
