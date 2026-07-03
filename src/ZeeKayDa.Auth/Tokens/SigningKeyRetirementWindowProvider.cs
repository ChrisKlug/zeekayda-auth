using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Default <see cref="ISigningKeyRetirementWindowProvider"/> implementation, deriving the
/// retirement window per ADR 0011 §3.3(a′).
/// </summary>
internal sealed class SigningKeyRetirementWindowProvider : ISigningKeyRetirementWindowProvider
{
    // Per ADR 0011 §3.3(a'): RetirementWindow = max(access-token lifetime, ID-token lifetime,
    // 1-hour floor) + ClockSkewTolerance. Today NEITHER token-lifetime term is configurable yet
    // (no ID-token lifetime property, no JWT-access-token lifetime property exists), so the
    // 1-hour floor is currently the only real term. When configurable per-token lifetimes are
    // added to AuthorizationServerOptions, THIS derivation must be extended to take the max with
    // them — not replaced.
    private static readonly TimeSpan Floor = TimeSpan.FromHours(1);

    private readonly IOptions<AuthorizationServerOptions> _options;

    /// <summary>
    /// Initialises the provider with the authorization server options carrying
    /// <see cref="AuthorizationServerOptions.ClockSkewTolerance"/>.
    /// </summary>
    /// <param name="options">The authorization server options.</param>
    public SigningKeyRetirementWindowProvider(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public TimeSpan GetRetirementWindow() => Floor + _options.Value.ClockSkewTolerance;
}
