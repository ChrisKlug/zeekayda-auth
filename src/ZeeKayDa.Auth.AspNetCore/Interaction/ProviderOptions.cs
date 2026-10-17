namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// How the host takes part in an external provider sign-in. Configured through the second
/// argument of <c>WithProviders</c>.
/// </summary>
public sealed class ProviderOptions
{
    /// <summary>
    /// Gets or sets the handler that runs when a provider has authenticated the user, before the
    /// SSO session is established. <see langword="null"/> (the default) promotes the principal as it is.
    /// </summary>
    /// <remarks>
    /// The handler may end the request with <see cref="ProviderSignInContext.RedirectToAsync"/>,
    /// sending the user to a host page that finishes through <see cref="ProviderSignInInteraction"/>,
    /// or with <see cref="ProviderSignInContext.DenyAsync"/>. Calling neither promotes the principal.
    /// This is where a host chooses the subject an external user gets, through
    /// <see cref="ProviderSignInInteraction.SignInWithReplacedAccountAsync(string, IEnumerable{string}, System.Security.Claims.Claim[])"/>
    /// on that page; otherwise the default <see cref="ExternalSubject.Derive"/>(issuer, subject) applies.
    /// </remarks>
    public Func<ProviderSignInContext, Task>? OnProviderSignIn { get; set; }

    /// <summary>
    /// Gets or sets the handler that runs before the user is sent to a provider, to forward what
    /// the client's authorization request asks of the authentication in the form that provider's
    /// handler reads. <see langword="null"/> (the default) sends every challenge as it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OpenID Connect Core §3.1.2.3 requires the authorization server to re-authenticate the user
    /// when the request carries <c>prompt=login</c> or a <c>max_age</c> the session has outlived.
    /// A provider with a live session of its own would otherwise answer without asking the user,
    /// so when <see cref="ProviderChallengeContext.ReauthenticationRequired"/> is set, the
    /// challenge proceeds only if the handler returns <see cref="ProviderChallengeOutcome.Reauthenticating"/>.
    /// That is a claim the framework acts on, recording the authentication as fresh: return it
    /// only for a provider known to honour what the handler set. Under a re-authentication demand,
    /// <see cref="ProviderChallengeOutcome.Proceed"/> and no handler at all answer the client with
    /// <c>login_required</c> instead of challenging (§3.1.2.1), as <see cref="ProviderChallengeOutcome.Refuse"/>
    /// always does; a handler that throws or returns <see langword="null"/> answers it with
    /// <c>server_error</c>.
    /// </para>
    /// <para>
    /// One handler serves every provider, from every <c>WithProviders</c> call, and a later call
    /// that sets it replaces the handler an earlier one set. Branch on
    /// <see cref="ProviderChallengeContext.Provider"/>, which names the provider being challenged.
    /// </para>
    /// </remarks>
    /// <example>
    /// For a provider registered with ASP.NET Core's OpenID Connect handler, which reads the
    /// <c>prompt</c> and <c>max_age</c> it sends upstream from the challenge properties:
    /// <code>
    /// options.OnProviderChallenge = ctx =>
    /// {
    ///     if (!ctx.ReauthenticationRequired)
    ///         return ProviderChallengeOutcome.Proceed;
    ///
    ///     ctx.Properties.SetParameter(OpenIdConnectChallengeProperties.PromptKey, "login");
    ///     ctx.Properties.SetParameter(OpenIdConnectChallengeProperties.MaxAgeKey, ctx.MaxAge);
    ///
    ///     return ProviderChallengeOutcome.Reauthenticating;
    /// };
    /// </code>
    /// </example>
    public Func<ProviderChallengeContext, ProviderChallengeOutcome>? OnProviderChallenge { get; set; }
}
