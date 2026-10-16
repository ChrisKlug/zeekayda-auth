using Microsoft.AspNetCore.Authentication;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Fails startup when a provider's handler cannot handle requests, so its callback could never
/// complete a sign-in.
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

        return Task.CompletedTask;
    }

    private static bool HandlesRequests(ProviderRegistration registration) =>
        typeof(IAuthenticationRequestHandler).IsAssignableFrom(registration.HandlerType);
}
