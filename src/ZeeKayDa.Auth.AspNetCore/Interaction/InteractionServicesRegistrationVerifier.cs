using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Fails startup when an interaction service is registered as anything but the framework's own
/// implementation, keyed or not, before or after <c>AddZeeKayDaAuth</c>.
/// </summary>
/// <remarks>
/// The interaction services are how a page completes a protocol step: they bind the step to its
/// interaction, record the outcome and answer the client. A host's replacement would decide all of
/// that, so they are consumed, never implemented. The collection is read rather than the provider,
/// so the check builds nothing.
/// </remarks>
internal sealed class InteractionServicesRegistrationVerifier(ServiceLifetimeScanner scanner) : IStartupVerifier
{
    /// <summary>Each interaction service, with the one implementation the framework registers for it.</summary>
    internal static readonly IReadOnlyDictionary<Type, Type> FrameworkImplementations = new Dictionary<Type, Type>
    {
        [typeof(ILoginInteraction)] = typeof(LoginInteraction),
        [typeof(IConsentInteraction)] = typeof(ConsentInteraction),
        [typeof(IErrorInteraction)] = typeof(ErrorInteraction),
        [typeof(ILogoutInteraction)] = typeof(LogoutInteraction),
        [typeof(IProviderSignInInteraction)] = typeof(ProviderSignInInteraction),
    };

    /// <inheritdoc/>
    public string Name => "InteractionServicesRegistration";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        foreach (var (service, implementation) in FrameworkImplementations)
        {
            if (scanner.AllRegistrationsOf(service).Any(descriptor => IsNotTheFrameworks(descriptor, implementation)))
            {
                context.AddFailure(
                    "interaction.service.replaced",
                    $"{service.Name} is registered by the host. The interaction services complete each " +
                    "protocol step for a page, so the framework owns them; a page injects and calls " +
                    $"{service.Name}. Remove the {service.Name} registration.");
            }
        }

        return Task.CompletedTask;
    }

    // The framework registers no keyed interaction service, so every keyed one is the host's.
    private static bool IsNotTheFrameworks(ServiceDescriptor descriptor, Type implementation) =>
        descriptor.IsKeyedService || descriptor.ImplementationType != implementation;
}
