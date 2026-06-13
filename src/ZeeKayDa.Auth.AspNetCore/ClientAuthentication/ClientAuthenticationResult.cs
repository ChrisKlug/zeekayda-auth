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

    /// <summary>Returns a successful authentication result.</summary>
    public static ClientAuthenticationResult Valid() => new() { Authenticated = true };

    /// <summary>Returns a failed authentication result.</summary>
    public static ClientAuthenticationResult NotValid() => new() { Authenticated = false };
}
