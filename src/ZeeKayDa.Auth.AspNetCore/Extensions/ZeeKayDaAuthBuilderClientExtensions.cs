using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.Clients;
using ZeeKayDa.Auth.Clients;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering client repositories with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderClientExtensions
{
    /// <summary>
    /// Registers an in-memory client repository populated by the given <paramref name="configure"/> callback.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">
    /// A callback that receives an <see cref="IInMemoryClientRegistrationBuilder"/> to register
    /// clients.
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="configure"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Multiple calls are additive — client registrations accumulate. The repository is validated
    /// and constructed (including secret hashing) at host startup, so misconfiguration (duplicate
    /// client_id, invalid client, hashing failure) fails fast rather than at the first request.
    /// </remarks>
    public static ZeeKayDaAuthBuilder AddInMemoryClients(
        this ZeeKayDaAuthBuilder builder,
        Action<IInMemoryClientRegistrationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // A custom IClientRepository registered before this call would silently win the
        // TryAddSingleton below, leaving the configured in-memory clients unreachable. Detect that
        // and fail loudly rather than no-op.
        var existing = builder.Services.FirstOrDefault(sd =>
            sd.ServiceType == typeof(IClientRepository) &&
            sd.ImplementationType != typeof(InMemoryClientRepository));
        if (existing is not null)
        {
            throw new InvalidOperationException(
                $"AddInMemoryClients was called after a custom IClientRepository " +
                $"({existing.ImplementationType?.Name ?? "unknown"}) was already registered. " +
                "Call AddInMemoryClients before registering a custom repository, or populate " +
                "the custom repository directly rather than using AddInMemoryClients.");
        }

        // Obtain or create the concrete options object. Multiple AddInMemoryClients calls share the
        // same instance so registrations accumulate. Registering the concrete type as a singleton
        // avoids capturing closures: the builder adds specs directly to the list, and when the
        // repository clears the list at startup the specs become GC-eligible immediately.
        var optionsDescriptor = builder.Services
            .FirstOrDefault(sd => sd.ServiceType == typeof(InMemoryClientRegistrationOptions));

        InMemoryClientRegistrationOptions opts;
        if (optionsDescriptor is not null)
        {
            // A previous AddInMemoryClients call already registered the singleton — reuse it.
            opts = (InMemoryClientRegistrationOptions)optionsDescriptor.ImplementationInstance!;
        }
        else
        {
            opts = new InMemoryClientRegistrationOptions();
            builder.Services.AddSingleton(opts);
            builder.Services.AddSingleton<IOptions<InMemoryClientRegistrationOptions>>(
                new OptionsWrapper<InMemoryClientRegistrationOptions>(opts));
        }

        var registration = new InMemoryClientRegistrationBuilder(opts);
        configure(registration);

        builder.Services.TryAddSingleton<IClientRepository, InMemoryClientRepository>();

        return builder;
    }
}
