using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// The outcome of authorization request validation — a closed union mirroring the two-phase
/// error model: local errors before the redirect target is authenticated, redirect errors after.
/// </summary>
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

        /// <summary>
        /// A generic human-readable description. Never echoes a request value, and is identical
        /// for unknown-client and unregistered-redirect failures (enumeration defence).
        /// </summary>
        public required string Description { get; init; }
    }

    /// <summary>
    /// Phase-2 failure: the redirect target is authenticated, so the error is delivered to the
    /// client per RFC 6749 §4.1.2.1, with <c>state</c> echoed when present and <c>iss</c> always.
    /// </summary>
    public sealed class RedirectError : AuthorizeRequestValidationResult
    {
        /// <summary>The exact registered redirect URI the error is sent to.</summary>
        public required string RedirectUri { get; init; }

        /// <summary>The OAuth error code.</summary>
        public required string Error { get; init; }

        /// <summary>
        /// A generic human-readable description naming the offending parameter, never its value.
        /// </summary>
        public required string Description { get; init; }

        /// <summary>The client's <c>state</c> value to echo byte for byte, if one was sent.</summary>
        public required string? State { get; init; }
    }
}
