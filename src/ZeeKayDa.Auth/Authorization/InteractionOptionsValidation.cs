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
                "configuration.authorization_endpoint.interaction.consent_path.unsafe"));
}
