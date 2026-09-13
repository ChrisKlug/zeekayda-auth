namespace ZeeKayDa.Auth.Tokens;

/// <summary>The <c>error</c> codes a token response may carry (RFC 6749 §5.2).</summary>
internal static class TokenRequestErrors
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnauthorizedClient = "unauthorized_client";
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>
    /// Borrowed from the authorization endpoint's list (RFC 6749 §4.1.2.1): §5.2's own list is
    /// closed and blames the client for everything, so a server fault needs a code from outside it.
    /// </summary>
    public const string ServerError = "server_error";
}
