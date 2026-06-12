namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The outcome of a client authentication attempt at the token endpoint.
/// </summary>
/// <remarks>
/// Use <see cref="Valid"/> and <see cref="NotValid"/> to create instances.
/// </remarks>
public sealed class ClientAuthenticationResult
{
    private ClientAuthenticationResult() { }

    /// <summary>
    /// <see langword="true"/> if the client was successfully authenticated;
    /// <see langword="false"/> if authentication failed.
    /// </summary>
    public bool Authenticated { get; private init; }

    /// <summary>
    /// The OAuth 2.0 error code to include in a token error response on failure.
    /// <see langword="null"/> when <see cref="Authenticated"/> is <see langword="true"/>.
    /// Defaults to <c>invalid_client</c> as required by RFC 6749 §5.2.
    /// </summary>
    public string? Error { get; private init; }

    /// <summary>Returns a successful authentication result.</summary>
    public static ClientAuthenticationResult Valid() => new() { Authenticated = true };

    /// <summary>Returns a failed authentication result with <see cref="Error"/> set to <c>invalid_client</c>.</summary>
    public static ClientAuthenticationResult NotValid() => new() { Authenticated = false, Error = "invalid_client" };
}
