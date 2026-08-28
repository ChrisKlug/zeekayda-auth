namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The details of an authorization request error that could not be redirected to the client,
/// as surfaced to the host's error page via <see cref="IErrorInteraction"/>.
/// </summary>
public sealed record AuthorizationErrorDetails
{
    /// <summary>The OAuth 2.0 error code (RFC 6749 §4.1.2.1), e.g. <c>invalid_request</c>.</summary>
    public required string Error { get; init; }

    /// <summary>
    /// A generic human-readable description safe to render. Never contains request values.
    /// </summary>
    public required string Description { get; init; }
}
