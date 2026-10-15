using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>Where a request that must authenticate its user is sent, decided from configuration.</summary>
internal enum LoginDispatchRule
{
    /// <summary>A login page is needed and configured: redirect there.</summary>
    LoginPage,

    /// <summary>Local sign-in off and exactly one provider: straight there, whatever the login path.</summary>
    SingleProvider,

    /// <summary>
    /// A login page is needed — local sign-in, or providers to choose between — but not configured.
    /// Warned at startup, <c>server_error</c> at runtime.
    /// </summary>
    PageNeeded,

    /// <summary>Local sign-in off and no providers: nothing can authenticate anyone. A startup failure.</summary>
    NoSignInMethod,
}

/// <summary>The dispatch rules: whether a page is needed is decided first; the login path is only where it lives.</summary>
internal static class LoginDispatch
{
    public static LoginDispatchRule Decide(InteractionOptions interaction, int providerCount)
    {
        ArgumentNullException.ThrowIfNull(interaction);
        ArgumentOutOfRangeException.ThrowIfNegative(providerCount);

        if (!interaction.SupportsLocalSignIn && providerCount == 0)
            return LoginDispatchRule.NoSignInMethod;

        if (!interaction.SupportsLocalSignIn && providerCount == 1)
            return LoginDispatchRule.SingleProvider;

        if (interaction.LoginPath is not null)
            return LoginDispatchRule.LoginPage;

        return LoginDispatchRule.PageNeeded;
    }

    /// <summary>The login page provider challenges start from and return to; <see langword="null"/> without one.</summary>
    public static string? LoginPageFor(InteractionOptions interaction, int providerCount) =>
        Decide(interaction, providerCount) == LoginDispatchRule.LoginPage ? interaction.LoginPath : null;
}
