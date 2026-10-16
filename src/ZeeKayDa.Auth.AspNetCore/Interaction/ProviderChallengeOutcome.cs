namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What <see cref="ProviderOptions.OnProviderChallenge"/> decides about a challenge to an external
/// provider. A closed set: <see cref="Proceed"/>, <see cref="Reauthenticating"/> or <see cref="Refuse"/>.
/// </summary>
public sealed class ProviderChallengeOutcome
{
    /// <summary>
    /// Send the challenge as it is. When <see cref="ProviderChallengeContext.ReauthenticationRequired"/>
    /// is <see langword="true"/>, the client is answered with <c>login_required</c> instead and no
    /// challenge is sent.
    /// </summary>
    public static readonly ProviderChallengeOutcome Proceed = new();

    /// <summary>
    /// Send the challenge: the hook has set on <see cref="ProviderChallengeContext.Properties"/>
    /// what makes this provider re-authenticate the user rather than answer from a session it
    /// already holds.
    /// </summary>
    /// <remarks>
    /// A claim the framework acts on: the authentication the provider returns is recorded as
    /// happening now, and the ID token's <c>auth_time</c> says so. Return it only for a provider
    /// known to honour what the hook set.
    /// </remarks>
    public static readonly ProviderChallengeOutcome Reauthenticating = new();

    /// <summary>Send no challenge; the client is answered with <c>login_required</c>.</summary>
    public static readonly ProviderChallengeOutcome Refuse = new();

    private ProviderChallengeOutcome()
    {
    }
}
