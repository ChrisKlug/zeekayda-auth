using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The outcome of a client authentication attempt at the token endpoint.
/// </summary>
/// <remarks>
/// An authenticator that checked a client secret returns <see cref="From"/>; one that refused without
/// checking a secret returns <see cref="NotValid"/>, and the token endpoint pads that refusal so it
/// takes as long as a wrong secret.
/// </remarks>
public sealed class ClientAuthenticationResult
{
    private ClientAuthenticationResult() { }

    /// <summary>
    /// <see langword="true"/> if the client was successfully authenticated;
    /// <see langword="false"/> if authentication failed.
    /// </summary>
    public bool Authenticated { get; private init; }

    /// <summary>Whether a failure already spent its timing padding inside <see cref="IClientSecrets.Verify"/>.</summary>
    internal bool FailurePadded { get; private init; }

    /// <summary>Returns a successful authentication result.</summary>
    public static ClientAuthenticationResult Valid() => new() { Authenticated = true };

    /// <summary>
    /// Returns a failed authentication result for a request refused without checking a client secret.
    /// The token endpoint pads it.
    /// </summary>
    public static ClientAuthenticationResult NotValid() => new() { Authenticated = false };

    /// <summary>Returns the result of checking a client secret with <see cref="IClientSecrets.Verify"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="verification"/> is <see langword="null"/>.</exception>
    public static ClientAuthenticationResult From(SecretVerification verification)
    {
        ArgumentNullException.ThrowIfNull(verification);
        return new() { Authenticated = verification.Matched, FailurePadded = verification.TryClaimPadding() };
    }
}
