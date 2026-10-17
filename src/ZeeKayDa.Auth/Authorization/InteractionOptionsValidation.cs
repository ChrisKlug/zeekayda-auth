using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

internal static class InteractionOptionsValidation
{
    /// <summary>
    /// The most accounts one browser may hold. Each is a few hundred bytes of the session cookie, and
    /// past this the cookie nears the size servers refuse a request header at.
    /// </summary>
    internal const int MaxSignedInAccountsLimit = 20;

    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this InteractionOptions interaction) =>
        InteractionPath.Validate(
                interaction.ErrorPath,
                "AuthorizationEndpoint.Interaction.ErrorPath",
                "configuration.authorization_endpoint.interaction.error_path.unsafe")
            .Concat(InteractionPath.Validate(
                interaction.LoginPath,
                "AuthorizationEndpoint.Interaction.LoginPath",
                "configuration.authorization_endpoint.interaction.login_path.unsafe"))
            .Concat(InteractionPath.Validate(
                interaction.ConsentPath,
                "AuthorizationEndpoint.Interaction.ConsentPath",
                "configuration.authorization_endpoint.interaction.consent_path.unsafe"))
            .Concat(InteractionPath.Validate(
                interaction.SelectAccountPath,
                "AuthorizationEndpoint.Interaction.SelectAccountPath",
                "configuration.authorization_endpoint.interaction.select_account_path.unsafe"))
            .Concat(ValidateMaxSignedInAccounts(interaction));

    private static IEnumerable<ZeeKayDaConfigurationFailure> ValidateMaxSignedInAccounts(InteractionOptions interaction)
    {
        if (interaction.MaxSignedInAccounts < 1)
        {
            yield return new(
                "configuration.authorization_endpoint.interaction.max_signed_in_accounts.not_positive",
                "AuthorizationServerOptions.AuthorizationEndpoint.Interaction.MaxSignedInAccounts must be at least 1.");
        }

        if (interaction.MaxSignedInAccounts > MaxSignedInAccountsLimit)
        {
            yield return new(
                "configuration.authorization_endpoint.interaction.max_signed_in_accounts.too_large",
                $"AuthorizationServerOptions.AuthorizationEndpoint.Interaction.MaxSignedInAccounts must be at most {MaxSignedInAccountsLimit}: "
                + "every account is part of the session cookie, and a larger cookie can be refused as a request header.");
        }
    }
}
