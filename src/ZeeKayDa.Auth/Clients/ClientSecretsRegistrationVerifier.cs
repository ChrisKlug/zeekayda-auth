using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Fails startup when <see cref="IClientSecrets"/> is registered as anything but the framework's own
/// <see cref="ClientSecrets"/>, keyed or not, before or after <c>AddZeeKayDaAuth</c>.
/// </summary>
/// <remarks>
/// A third-party authenticator verifies, and pads its refusals, through whatever resolves as
/// <see cref="IClientSecrets"/>; a host's replacement would decide both. The collection is read rather
/// than the provider, so the check builds nothing.
/// </remarks>
internal sealed class ClientSecretsRegistrationVerifier(ServiceLifetimeScanner scanner) : IStartupVerifier
{
    /// <summary>The one registration of <see cref="IClientSecrets"/> the framework makes.</summary>
    internal static readonly Func<IServiceProvider, IClientSecrets> FrameworkInstance =
        services => services.GetRequiredService<ClientSecrets>();

    /// <inheritdoc/>
    public string Name => "ClientSecretsRegistration";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (scanner.AllRegistrationsOf(typeof(IClientSecrets)).Any(IsNotTheFrameworks))
        {
            context.AddFailure(
                "clients.secrets.replaced",
                "IClientSecrets is registered by the host. It verifies client secrets and pads failed " +
                "client authentication against timing attacks, so the framework owns it; a new algorithm " +
                "is an IClientSecretHasher, registered with AddClientSecretHasher<T>(). Remove the " +
                "IClientSecrets registration.");
        }

        return Task.CompletedTask;
    }

    // The framework registers no keyed IClientSecrets, so every keyed one is the host's.
    private static bool IsNotTheFrameworks(ServiceDescriptor descriptor) =>
        descriptor.IsKeyedService || !ReferenceEquals(descriptor.ImplementationFactory, FrameworkInstance);
}
