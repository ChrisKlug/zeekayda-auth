using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The framework-owned scheme map: every external provider <c>WithProviders</c> observed, and the
/// only place those schemes exist. Immutable — each <c>WithProviders</c> call builds a new
/// registry from the previous one and re-registers it.
/// </summary>
/// <remarks>
/// Names are matched ordinally, as scheme names are everywhere in ASP.NET Core, and registered
/// uniquely ignoring case, because routing and <c>PathString</c> comparison are case-insensitive
/// and two providers whose callback routes differ only by case would share one.
/// </remarks>
internal sealed class ProviderRegistry
{
    public static readonly ProviderRegistry Empty = new([]);

    private readonly ImmutableArray<ProviderRegistration> _registrations;

    private ProviderRegistry(ImmutableArray<ProviderRegistration> registrations)
    {
        _registrations = registrations;
        Descriptors = registrations
            .Select(registration => registration.Descriptor)
            .ToImmutableArray();
    }

    /// <summary>
    /// The registry currently registered in <paramref name="services"/>, or <see cref="Empty"/>
    /// when <c>WithProviders</c> has not been called yet.
    /// </summary>
    public static ProviderRegistry FindIn(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return services
            .Where(descriptor => descriptor.ServiceType == typeof(ProviderRegistry))
            .Select(descriptor => descriptor.ImplementationInstance as ProviderRegistry)
            .LastOrDefault() ?? Empty;
    }

    /// <summary>
    /// Registers <paramref name="registry"/> as the one and only registry, replacing whatever was
    /// registered before.
    /// </summary>
    public static void RegisterIn(IServiceCollection services, ProviderRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(registry);

        var existing = services
            .Where(descriptor => descriptor.ServiceType == typeof(ProviderRegistry))
            .ToArray();

        foreach (var descriptor in existing)
            services.Remove(descriptor);

        services.AddSingleton(registry);
    }

    /// <summary>
    /// Returns a registry holding these registrations and <paramref name="added"/>, refusing a
    /// name outside the grammar, a reserved framework name, or one already registered, ignoring
    /// case.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A name in <paramref name="added"/> does not satisfy <see cref="ProviderName"/>, is one of
    /// the framework's reserved cookie or scheme names, or collides with a registered one ignoring
    /// case.
    /// </exception>
    public ProviderRegistry Add(IEnumerable<ProviderRegistration> added)
    {
        ArgumentNullException.ThrowIfNull(added);

        var combined = _registrations.ToBuilder();
        var seen = new HashSet<string>(
            _registrations.Select(registration => registration.Name),
            StringComparer.OrdinalIgnoreCase);

        foreach (var registration in added)
        {
            if (!ProviderName.IsValid(registration.Name))
            {
                throw new InvalidOperationException(
                    $"The provider name '{registration.Name}' is not valid. A provider name is " +
                    $"{ProviderName.Grammar}: it becomes a segment of the provider's callback route.");
            }

            // The scheme-backed reserved names would be caught at startup as a collision with the
            // framework's own schemes; zkd.interaction has no scheme behind it and would not be.
            // Refusing all four here is one rule instead of two.
            if (ZeeKayDaCookies.ReservedNames.Contains(registration.Name, StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The provider name '{registration.Name}' is reserved by ZeeKayDa.Auth. Choose another name.");
            }

            if (!seen.Add(registration.Name))
            {
                throw new InvalidOperationException(
                    $"A provider named '{registration.Name}' is already registered. Provider names " +
                    "must be unique ignoring case, because their callback routes are matched " +
                    "case-insensitively.");
            }

            combined.Add(registration);
        }

        return new ProviderRegistry(combined.ToImmutable());
    }

    /// <summary>Whether <paramref name="name"/> is a registered provider, compared ordinally.</summary>
    public bool Contains(string name) => Find(name) is not null;

    /// <summary>The registration named <paramref name="name"/>, compared ordinally, or <see langword="null"/>.</summary>
    public ProviderRegistration? Find(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return _registrations.FirstOrDefault(
            registration => string.Equals(registration.Name, name, StringComparison.Ordinal));
    }

    /// <summary>Every registered provider, in registration order.</summary>
    public IReadOnlyList<ProviderRegistration> Registrations => _registrations;

    /// <summary>What the login page sees: one descriptor per provider, in registration order.</summary>
    public IReadOnlyList<ProviderDescriptor> Descriptors { get; }

    public int Count => _registrations.Length;
}
