namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// An <see cref="IClientAuthenticator"/>'s answer to whether a token request carries its credential:
/// not its shape (<see cref="None"/>), its shape for one method (<see cref="For"/>), or its shape but
/// malformed or ambiguous (<see cref="Refused"/>).
/// </summary>
/// <remarks>
/// <see cref="Refused"/> carries no reason, so every client-authentication refusal is the same bare
/// <c>invalid_client</c> (RFC 6749 §5.2) and none tells the caller which check failed. It is not <see cref="None"/>, because a request no authenticator
/// claims falls through to the <c>none</c> method, which would accept a public client and ignore the
/// credential the request carried.
/// </remarks>
public sealed class ClientAuthenticatorMatch
{
    private ClientAuthenticatorMatch(string? method, bool isRefused)
    {
        Method = method;
        IsRefused = isRefused;
    }

    /// <summary>The request does not carry this authenticator's credential.</summary>
    public static ClientAuthenticatorMatch None { get; } = new(null, isRefused: false);

    /// <summary>The request carries this authenticator's credential, malformed or ambiguous.</summary>
    public static ClientAuthenticatorMatch Refused { get; } = new(null, isRefused: true);

    /// <summary>The request carries this authenticator's credential for <paramref name="method"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="method"/> is null or empty.</exception>
    public static ClientAuthenticatorMatch For(string method)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        return new(method, isRefused: false);
    }

    /// <summary>The matched method, or <see langword="null"/> for <see cref="None"/> and <see cref="Refused"/>.</summary>
    public string? Method { get; }

    /// <summary>Whether the request is this authenticator's shape but cannot be authenticated.</summary>
    public bool IsRefused { get; }
}
