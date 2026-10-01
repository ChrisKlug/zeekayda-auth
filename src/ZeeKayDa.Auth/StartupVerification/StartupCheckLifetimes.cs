using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Fails startup when an <see cref="IStartupVerifier"/> or <see cref="IStartupActivator"/> is
/// registered with any lifetime but scoped.
/// </summary>
/// <remarks>
/// The runner resolves each phase's checks from one scope. A singleton or transient check is built
/// from the root provider instead, so a scoped dependency it injects outlives the phase — silently in
/// Production, where scope validation is off. This runs before any check is resolved: with scope
/// validation on, resolving such a check throws, and the operator would see that instead of this.
/// </remarks>
internal static class StartupCheckLifetimes
{
    /// <summary>
    /// Throws one <see cref="ZeeKayDaConfigurationException"/> naming every non-scoped check, or
    /// returns when they are all scoped.
    /// </summary>
    public static void ThrowIfAnyNotScoped(ServiceLifetimeScanner scanner)
    {
        ZeeKayDaConfigurationFailure[] failures =
        [
            .. NotScoped<IStartupVerifier>(scanner),
            .. NotScoped<IStartupActivator>(scanner),
        ];

        if (failures.Length > 0)
            throw new ZeeKayDaConfigurationException(failures);
    }

    private static IEnumerable<ZeeKayDaConfigurationFailure> NotScoped<TCheck>(ServiceLifetimeScanner scanner) =>
        scanner.RegistrationsOf(typeof(TCheck))
            .Where(registration => registration.Lifetime != ServiceLifetime.Scoped)
            .Select(registration => new ZeeKayDaConfigurationFailure(
                "startup.check_not_scoped",
                $"'{Describe(registration)}' is registered as {typeof(TCheck).Name} with a " +
                $"{registration.Lifetime} lifetime. Register it with AddScoped: the runner resolves each " +
                "phase's checks from one scope, and any other lifetime builds the check, and the scoped " +
                "services it injects, outside that scope."));

    private static string Describe(ServiceDescriptor registration) =>
        (registration.ImplementationType
            ?? registration.ImplementationInstance?.GetType()
            ?? registration.ImplementationFactory?.Method.ReturnType)?.FullName
        ?? registration.ServiceType.FullName!;
}
