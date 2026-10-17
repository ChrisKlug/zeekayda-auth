using Microsoft.AspNetCore.Authentication;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// What <see cref="ProviderOptions.OnProviderChallenge"/> receives: the provider the user is about
/// to be sent to, what the client's authorization request asked of the authentication, and the
/// challenge properties the provider's handler will be given.
/// </summary>
public sealed class ProviderChallengeContext
{
    internal ProviderChallengeContext(
        ProviderDescriptor provider,
        IReadOnlySet<PromptValue> prompts,
        TimeSpan? maxAge,
        string? loginHint,
        bool reauthenticationRequired,
        AuthenticationProperties properties)
    {
        Provider = provider;
        Prompts = prompts;
        MaxAge = maxAge;
        LoginHint = loginHint;
        ReauthenticationRequired = reauthenticationRequired;
        Properties = properties;
    }

    /// <summary>The provider about to be challenged.</summary>
    public ProviderDescriptor Provider { get; }

    /// <summary>The <c>prompt</c> values the client sent, as it sent them.</summary>
    public IReadOnlySet<PromptValue> Prompts { get; }

    /// <summary>The client's <c>max_age</c>, or <see langword="null"/> when the request carried none.</summary>
    public TimeSpan? MaxAge { get; }

    /// <summary>The client's unverified <c>login_hint</c>, or <see langword="null"/>.</summary>
    public string? LoginHint { get; }

    /// <summary>
    /// Whether the client demands that the user authenticate again: the request carries
    /// <c>prompt=login</c>, or it carries a <see cref="MaxAge"/> and the user has no session, or one
    /// older than that.
    /// OpenID Connect Core §3.1.2.1 requires the authorization server to re-authenticate the user
    /// then, and, if it cannot, to return an error, typically <c>login_required</c>.
    /// </summary>
    /// <remarks>
    /// When this is <see langword="true"/>, only <see cref="ProviderChallengeOutcome.Reauthenticating"/>
    /// lets the challenge proceed; any other outcome answers the client with <c>login_required</c>.
    /// </remarks>
    public bool ReauthenticationRequired { get; }

    /// <summary>
    /// The properties of the challenge about to be sent, for the hook to set what its provider's
    /// handler reads. The framework re-applies its own items and
    /// <see cref="AuthenticationProperties.RedirectUri"/> after the hook returns, so the user's way
    /// back is unaffected by what the hook writes.
    /// </summary>
    public AuthenticationProperties Properties { get; }
}
