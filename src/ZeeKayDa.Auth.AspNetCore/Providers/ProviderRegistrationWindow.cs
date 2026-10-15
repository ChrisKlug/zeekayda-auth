using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Observes what a <c>WithProviders</c> callback registered, then takes the schemes for the
/// framework: each scheme-map configurer is replayed into a throwaway options object and removed,
/// so the host's <see cref="AuthenticationOptions"/> never sees them.
/// </summary>
/// <remarks>
/// Everything else the callback registered — handler types, named options — stays in the shared
/// container, which is what the handler needs to run.
/// </remarks>
internal static class ProviderRegistrationWindow
{
    /// <summary>
    /// Runs <paramref name="configure"/> and returns the schemes it registered, their scheme-map
    /// descriptors removed. A failure leaves the collection partly changed; the caller restores it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The callback did something other than append to the collection, registered a scheme-map
    /// configurer that cannot be replayed or that adds no scheme, registered a post-configurer or
    /// an open-generic configurer for <see cref="AuthenticationOptions"/>, or set an
    /// <see cref="AuthenticationOptions"/> default.
    /// </exception>
    public static IReadOnlyList<ProviderRegistration> Observe(
        IServiceCollection services,
        Action<AuthenticationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var before = services.ToArray();
        configure(new AuthenticationBuilder(services));
        EnsureOnlyAppended(services, before);

        var window = services.Skip(before.Length).ToArray();
        RefuseUnreadableConfiguration(window);

        var configurers = window
            .Where(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<AuthenticationOptions>))
            .ToArray();

        var (observed, everyConfigurerAddedAScheme) = Replay(configurers);
        RefuseDefaults(observed);
        if (!everyConfigurerAddedAScheme)
        {
            throw new InvalidOperationException(
                "The WithProviders callback configured AuthenticationOptions without adding a scheme. " +
                "Only scheme registrations belong inside WithProviders; anything else for " +
                "AuthenticationOptions belongs on AddAuthentication, outside it.");
        }

        foreach (var descriptor in configurers)
            services.Remove(descriptor);

        return observed.Schemes
            .Select(builder => builder.Build())
            .Select(scheme => new ProviderRegistration(scheme.Name, scheme.DisplayName, scheme.HandlerType))
            .ToArray();
    }

    /// <summary>Refuses anything but appending: an edit ahead of the window could hide a scheme from the replay.</summary>
    private static void EnsureOnlyAppended(IServiceCollection services, ServiceDescriptor[] before)
    {
        var intact = services.Count >= before.Length
            && before.Select((descriptor, index) => ReferenceEquals(descriptor, services[index])).All(same => same);

        if (!intact)
        {
            throw new InvalidOperationException(
                "The WithProviders callback changed service registrations that existed before it ran. " +
                "It may only add registrations: the framework learns which schemes were registered by " +
                "reading what the callback appended, and a callback that removes or reorders earlier " +
                "registrations could leave a scheme the framework never saw.");
        }
    }

    /// <summary>Refuses scheme-map configurers the replay cannot see: post-configurers and open generics.</summary>
    private static void RefuseUnreadableConfiguration(ServiceDescriptor[] window)
    {
        if (window.Any(descriptor => descriptor.ServiceType == typeof(IPostConfigureOptions<AuthenticationOptions>)))
        {
            throw new InvalidOperationException(
                "The WithProviders callback registered an IPostConfigureOptions<AuthenticationOptions>. " +
                "Provider schemes never reach the host's AuthenticationOptions, so nothing there can be " +
                "post-configured; register it outside WithProviders if it is meant for the host's own " +
                "schemes.");
        }

        if (window.Any(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<>)
            || descriptor.ServiceType == typeof(IPostConfigureOptions<>)))
        {
            throw new InvalidOperationException(
                "The WithProviders callback registered an open-generic IConfigureOptions<> or " +
                "IPostConfigureOptions<>, which would configure AuthenticationOptions without the " +
                "framework being able to read what it adds. Register it outside WithProviders.");
        }
    }

    /// <summary>
    /// Replays each instance-registered scheme-map configurer, the only kind that can be read and
    /// removed, and reports whether every one added a scheme.
    /// </summary>
    private static (AuthenticationOptions Observed, bool EveryConfigurerAddedAScheme) Replay(
        ServiceDescriptor[] configurers)
    {
        var observed = new AuthenticationOptions();
        var everyConfigurerAddedAScheme = true;

        foreach (var descriptor in configurers)
        {
            if (descriptor.IsKeyedService
                || descriptor.ImplementationInstance is not IConfigureOptions<AuthenticationOptions> configurer)
            {
                throw new InvalidOperationException(
                    "The WithProviders callback registered an IConfigureOptions<AuthenticationOptions> " +
                    "that is not an instance, so the framework cannot read which schemes it adds. " +
                    "Register provider schemes through the AuthenticationBuilder the callback receives.");
            }

            var schemesBefore = observed.Schemes.Count();
            configurer.Configure(observed);
            everyConfigurerAddedAScheme &= observed.Schemes.Count() > schemesBefore;
        }

        return (observed, everyConfigurerAddedAScheme);
    }

    /// <summary>Refuses a configurer that also set a default, which belongs on <c>AddAuthentication</c>.</summary>
    private static void RefuseDefaults(AuthenticationOptions observed)
    {
        var setsDefault = observed.DefaultScheme is not null
            || observed.DefaultAuthenticateScheme is not null
            || observed.DefaultChallengeScheme is not null
            || observed.DefaultForbidScheme is not null
            || observed.DefaultSignInScheme is not null
            || observed.DefaultSignOutScheme is not null
            || !observed.RequireAuthenticatedSignIn;

        if (setsDefault)
        {
            throw new InvalidOperationException(
                "The WithProviders callback set an AuthenticationOptions default. Provider schemes are " +
                "not in the host's scheme map and cannot be a default for it; set the host's own " +
                "defaults on AddAuthentication, outside WithProviders.");
        }
    }
}
