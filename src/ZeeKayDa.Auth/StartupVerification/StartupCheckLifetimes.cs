using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Fails startup on a startup check not registered as scoped, before any check is resolved; such a
/// check would capture scoped dependencies outside the phase's scope.
/// </summary>
internal static class StartupCheckLifetimes
{
    /// <summary>Throws one exception naming every non-scoped check, if there are any.</summary>
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
