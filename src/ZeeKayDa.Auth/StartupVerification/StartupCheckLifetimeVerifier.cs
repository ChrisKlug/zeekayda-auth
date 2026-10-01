using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Fails startup when an <see cref="IStartupVerifier"/> or <see cref="IStartupActivator"/> is
/// registered with any lifetime but scoped.
/// </summary>
/// <remarks>
/// The runner resolves each phase's checks from one scope. A singleton or transient check is built
/// from the root provider instead, so a scoped dependency it injects outlives the phase — silently in
/// Production, where scope validation is off. A misregistered activator is reported here, in the
/// verifier phase, before any activator is constructed.
/// </remarks>
internal sealed class StartupCheckLifetimeVerifier(ServiceLifetimeScanner scanner) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "StartupCheckLifetime";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        Check<IStartupVerifier>(context);
        Check<IStartupActivator>(context);
        return Task.CompletedTask;
    }

    private void Check<TCheck>(StartupVerificationContext context)
    {
        foreach (var registration in scanner.RegistrationsOf(typeof(TCheck))
                     .Where(registration => registration.Lifetime != ServiceLifetime.Scoped))
        {
            context.AddFailure(
                "startup.check_not_scoped",
                $"'{Describe(registration)}' is registered as {typeof(TCheck).Name} with a " +
                $"{registration.Lifetime} lifetime. Register it with AddScoped: the runner resolves each " +
                "phase's checks from one scope, and any other lifetime builds the check, and the scoped " +
                "services it injects, outside that scope.");
        }
    }

    private static string Describe(ServiceDescriptor registration) =>
        (registration.ImplementationType
            ?? registration.ImplementationInstance?.GetType()
            ?? registration.ImplementationFactory?.Method.ReturnType)?.FullName
        ?? registration.ServiceType.FullName!;
}
