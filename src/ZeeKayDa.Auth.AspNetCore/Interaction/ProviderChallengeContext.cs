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
        string? requiredSubject,
        bool reauthenticationRequired,
        AuthenticationProperties properties)
    {
        Provider = provider;
        Prompts = prompts;
        MaxAge = maxAge;
        LoginHint = loginHint;
        RequiredSubject = requiredSubject;
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
    /// The subject the client's <c>id_token_hint</c> names, or <see langword="null"/> when it sent
    /// none. The user is sent to a provider with a hint only when the browser holds no account for
    /// that user, and a return as anyone else is answered <c>login_required</c> (OpenID Connect Core
    /// §3.1.2.2).
    /// </summary>
    /// <remarks>
    /// This is the session subject — for an external user the one <see cref="ExternalSubject.Derive"/>
    /// computes — so the provider cannot be told it directly. A host with a user store can map it to
    /// what the provider knows the user by and forward that as the provider's own <c>login_hint</c>;
    /// any host can ask the provider for a fresh sign-in or an account choice, so that a provider
    /// session for someone else does not answer silently.
    /// </remarks>
    /// <example>
    /// For a provider registered with ASP.NET Core's OpenID Connect handler:
    /// <code>
    /// options.OnProviderChallenge = ctx =>
    /// {
    ///     if (ctx.RequiredSubject is not null)
    ///         ctx.Properties.SetParameter(OpenIdConnectChallengeProperties.PromptKey, "select_account");
    ///
    ///     return ProviderChallengeOutcome.Proceed;
    /// };
    /// </code>
    /// </example>
    public string? RequiredSubject { get; }

    /// <summary>
    /// Whether the client demands that the user authenticate again: the request carries
    /// <c>prompt=login</c>, or it carries a <see cref="MaxAge"/> and the browser holds no account that
    /// answers the request, or one that authenticated longer ago than that.
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
