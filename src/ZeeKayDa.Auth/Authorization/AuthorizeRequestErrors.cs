namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// OAuth 2.0 / OpenID Connect authorization error codes returned by request validation
/// (RFC 6749 §4.1.2.1, OIDC Core 1.0 §3.1.2.6).
/// </summary>
internal static class AuthorizeRequestErrors
{
    public const string InvalidRequest = "invalid_request";
    public const string UnauthorizedClient = "unauthorized_client";
    public const string UnsupportedResponseType = "unsupported_response_type";
    public const string InvalidScope = "invalid_scope";
    public const string RequestNotSupported = "request_not_supported";
    public const string RequestUriNotSupported = "request_uri_not_supported";

    /// <summary>
    /// The request cannot be completed without authenticating the user, and the client asked for
    /// no interaction (OIDC Core 1.0 §3.1.2.6).
    /// </summary>
    public const string LoginRequired = "login_required";

    /// <summary>
    /// The user, or the authorization server on their behalf, refused the request
    /// (RFC 6749 §4.1.2.1).
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// The server cannot complete the request through a fault of its own — a configuration gap
    /// rather than anything the client sent (RFC 6749 §4.1.2.1).
    /// </summary>
    public const string ServerError = "server_error";
}
