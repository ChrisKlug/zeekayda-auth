using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Where an authorization request that must authenticate its user is sent, decided once from
/// configuration and read by both the authorization endpoint and the startup check that warns or
/// fails ahead of it.
/// </summary>
internal enum LoginDispatchRule
{
    /// <summary>A login page is configured: redirect there, always.</summary>
    LoginPage,

    /// <summary>
    /// No login page, local sign-in off, exactly one provider: the framework can choose, so the
    /// request goes straight to that provider.
    /// </summary>
    SingleProvider,

    /// <summary>
    /// No login page, but one is needed — local sign-in is on, or there are two or more providers
    /// and the framework never chooses between them. Warned at startup, <c>server_error</c> at
    /// runtime.
    /// </summary>
    PageNeeded,

    /// <summary>
    /// Local sign-in off and no providers: nothing can authenticate anyone. A startup failure.
    /// </summary>
    NoSignInMethod,
}

/// <summary>
/// The dispatch rules for an authorization request that must authenticate its user. The presence
/// of a login page is the override: the framework never skips a page the host built.
/// </summary>
internal static class LoginDispatch
{
    public static LoginDispatchRule Decide(InteractionOptions interaction, int providerCount)
    {
        ArgumentNullException.ThrowIfNull(interaction);
        ArgumentOutOfRangeException.ThrowIfNegative(providerCount);

        if (!interaction.SupportsLocalSignIn && providerCount == 0)
            return LoginDispatchRule.NoSignInMethod;

        if (interaction.LoginPath is not null)
            return LoginDispatchRule.LoginPage;

        if (!interaction.SupportsLocalSignIn && providerCount == 1)
            return LoginDispatchRule.SingleProvider;

        return LoginDispatchRule.PageNeeded;
    }
}
