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
}
