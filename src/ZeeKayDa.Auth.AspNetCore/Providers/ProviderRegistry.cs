using System.Collections.Immutable;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The framework-owned, immutable scheme map of every provider <c>WithProviders</c> observed.
/// </summary>
/// <remarks>
/// Matched ordinally, but unique ignoring case: callback routes compare case-insensitively.
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

    /// <summary>The registry registered in <paramref name="services"/>, or <see cref="Empty"/>.</summary>
    public static ProviderRegistry FindIn(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        return services
            .Where(descriptor => descriptor.ServiceType == typeof(ProviderRegistry))
            .Select(descriptor => descriptor.ImplementationInstance as ProviderRegistry)
            .LastOrDefault() ?? Empty;
    }

    /// <summary>Registers <paramref name="registry"/>, replacing whatever was registered before.</summary>
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

    /// <summary>A registry with <paramref name="added"/> too, refusing invalid, reserved or duplicate names.</summary>
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

            // All reserved names, including those no startup scheme check would catch.
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
