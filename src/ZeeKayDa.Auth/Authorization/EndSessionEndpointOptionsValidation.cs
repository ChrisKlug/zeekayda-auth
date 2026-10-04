using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

internal static class EndSessionEndpointOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this EndSessionEndpointOptions endSessionEndpoint) =>
        InteractionPath.Validate(
                endSessionEndpoint.LogoutPath,
                "EndSessionEndpoint.LogoutPath",
                "configuration.end_session_endpoint.logout_path.unsafe")
            .Concat(InteractionPath.Validate(
                endSessionEndpoint.SignedOutPath,
                "EndSessionEndpoint.SignedOutPath",
                "configuration.end_session_endpoint.signed_out_path.unsafe"));
}
