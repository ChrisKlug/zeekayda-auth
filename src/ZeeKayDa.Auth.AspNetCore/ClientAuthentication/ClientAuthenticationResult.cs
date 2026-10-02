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

    private SecretVerification? _verification;

    /// <summary>Returns a successful authentication result.</summary>
    public static ClientAuthenticationResult Valid() => new() { Authenticated = true };

    /// <summary>
    /// Returns a failed authentication result for a request refused without checking a client secret.
    /// The token endpoint pads it.
    /// </summary>
    public static ClientAuthenticationResult NotValid() => new() { Authenticated = false };

    /// <summary>Returns the result of checking a client secret with <see cref="IClientSecrets.Verify"/>.</summary>
    /// <remarks>
    /// A result, and the verification it carries, belong to the request that produced them: an
    /// authenticator never caches or shares either across requests.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="verification"/> is <see langword="null"/>.</exception>
    public static ClientAuthenticationResult From(SecretVerification verification)
    {
        ArgumentNullException.ThrowIfNull(verification);
        return new() { Authenticated = verification.Matched, _verification = verification };
    }

    /// <summary>
    /// Whether this failure already spent its timing padding, claimed when the token endpoint uses the
    /// result, so a result or verification returned again is padded like any other refusal.
    /// </summary>
    internal bool TryClaimPadding() => _verification?.TryClaimPadding() ?? false;
}
