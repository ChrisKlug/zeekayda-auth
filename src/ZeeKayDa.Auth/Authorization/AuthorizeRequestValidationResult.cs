using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>The outcome of authorization request validation: valid, a local error, or a redirect error.</summary>
internal abstract class AuthorizeRequestValidationResult
{
    private AuthorizeRequestValidationResult() { }

    /// <summary>The request passed both validation phases.</summary>
    public sealed class Valid : AuthorizeRequestValidationResult
    {
        /// <summary>The fully validated request.</summary>
        public required ValidatedAuthorizeRequest Request { get; init; }
    }

    /// <summary>
    /// Phase-1 failure: the redirect target could not be authenticated. MUST be rendered
    /// locally and MUST NOT redirect anywhere (RFC 6749 §4.1.2.1).
    /// </summary>
    public sealed class LocalError : AuthorizeRequestValidationResult
    {
        /// <summary>The OAuth error code.</summary>
        public required string Error { get; init; }

        /// <summary>A generic description, identical for an unknown client and an unregistered redirect URI.</summary>
        public required string Description { get; init; }
    }

    /// <summary>Phase-2 failure, delivered to the authenticated redirect target (RFC 6749 §4.1.2.1).</summary>
    public sealed class RedirectError : AuthorizeRequestValidationResult
    {
        /// <summary>The exact registered redirect URI the error is sent to.</summary>
        public required string RedirectUri { get; init; }

        /// <summary>The OAuth error code.</summary>
        public required string Error { get; init; }

        /// <summary>A generic description naming the offending parameter, never its value.</summary>
        public required string Description { get; init; }

        /// <summary>The client's <c>state</c> value to echo byte for byte, if one was sent.</summary>
        public required string? State { get; init; }
    }
}
