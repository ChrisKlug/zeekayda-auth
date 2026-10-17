using Microsoft.AspNetCore.Authentication;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Fails startup when a provider's handler cannot handle requests, so its callback could never
/// complete a sign-in; warns when a handler is outside the remote base class, whose callback
/// conventions the framework cannot pin.
/// </summary>
internal sealed class ProviderHandlerVerifier(ProviderRegistry registry) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ProviderHandlers";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var registration in registry.Registrations.Where(registration => !HandlesRequests(registration)))
        {
            context.AddFailure(
                "provider.handler_cannot_handle_requests",
                $"The handler for provider '{registration.Name}', {registration.HandlerType.FullName}, " +
                $"does not implement {nameof(IAuthenticationRequestHandler)}, so the provider's callback " +
                "can never complete a sign-in. Register a handler that handles its own callback, as " +
                $"every {nameof(RemoteAuthenticationHandler<RemoteAuthenticationOptions>)} does.");
        }

        foreach (var registration in registry.Registrations.Where(registration => !IsRemote(registration)))
        {
            context.AddWarning(
                "provider.handler_not_remote",
                "The handler for provider '{Provider}', {HandlerType}, does not derive from " +
                "RemoteAuthenticationHandler<TOptions>, so the framework cannot pin its callback path " +
                "or sign-in scheme. The host must make it handle its callback at {CallbackRoute} " +
                "under the issuer path and sign in to the {SignInScheme} scheme; otherwise the " +
                "provider's round trip is abandoned.",
                registration.Name,
                registration.HandlerType.FullName,
                "/connect/callback/" + registration.Name,
                ZeeKayDaSchemes.External);
        }

        return Task.CompletedTask;
    }

    private static bool HandlesRequests(ProviderRegistration registration) =>
        typeof(IAuthenticationRequestHandler).IsAssignableFrom(registration.HandlerType);

    private static bool IsRemote(ProviderRegistration registration)
    {
        for (var type = registration.HandlerType; type is not null; type = type.BaseType)
        {
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(RemoteAuthenticationHandler<>))
                return true;
        }

        return false;
    }
}
