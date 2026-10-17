using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

internal static class InteractionOptionsValidation
{
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
    }
}
