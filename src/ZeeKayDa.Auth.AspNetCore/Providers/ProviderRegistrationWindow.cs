using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Observes what a <c>WithProviders</c> callback registered, then takes the schemes for the
/// framework: every <see cref="IConfigureOptions{TOptions}"/> of <see cref="AuthenticationOptions"/>
/// the callback added is replayed into a throwaway options object to learn the schemes, and then
/// removed, so the host's own <see cref="AuthenticationOptions"/> never learns they exist.
/// </summary>
/// <remarks>
/// Every route into the scheme map — <c>AddScheme</c>, <c>AddRemoteScheme</c>,
/// <c>AddPolicyScheme</c>, and a raw handler added by configuring
/// <see cref="AuthenticationOptions"/> directly — ends as that one descriptor type, so the replay
/// sees them identically. Everything else the callback registered (handler types, named options,
/// their validation and post-configuration) stays in the shared container, which is exactly what
/// the handler needs to run.
/// </remarks>
internal static class ProviderRegistrationWindow
{
    /// <summary>
    /// Runs <paramref name="configure"/> against <paramref name="services"/> and returns the
    /// schemes it registered, having removed their scheme-map descriptors.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The callback did something other than append to the collection, registered a scheme-map
    /// configurer that cannot be replayed, registered a post-configurer for
    /// <see cref="AuthenticationOptions"/>, or set an <see cref="AuthenticationOptions"/> default.
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
        RefusePostConfiguration(window);

        var configurers = window
            .Where(descriptor => descriptor.ServiceType == typeof(IConfigureOptions<AuthenticationOptions>))
            .ToArray();

        var observed = Replay(configurers);
        RefuseDefaults(observed);

        foreach (var descriptor in configurers)
            services.Remove(descriptor);

        return observed.Schemes
            .Select(builder => builder.Build())
            .Select(scheme => new ProviderRegistration(scheme.Name, scheme.DisplayName, scheme.HandlerType))
            .ToArray();
    }

    /// <summary>
    /// The window is the tail of the collection, and only that. A callback that removed,
    /// reordered or inserted ahead of an existing descriptor could leave a scheme in the host's
    /// map the replay never saw.
    /// </summary>
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

    private static void RefusePostConfiguration(ServiceDescriptor[] window)
    {
        if (window.Any(descriptor => descriptor.ServiceType == typeof(IPostConfigureOptions<AuthenticationOptions>)))
        {
            throw new InvalidOperationException(
                "The WithProviders callback registered an IPostConfigureOptions<AuthenticationOptions>. " +
                "Provider schemes never reach the host's AuthenticationOptions, so nothing there can be " +
                "post-configured; register it outside WithProviders if it is meant for the host's own " +
                "schemes.");
        }
    }

    /// <summary>
    /// Replays each scheme-map configurer into a throwaway options object. Only an instance
    /// registration can be replayed — a factory or type registration can neither be read here nor
    /// safely removed — and <c>AuthenticationBuilder</c> registers instances, so a host hits this
    /// only by registering the interface itself.
    /// </summary>
    private static AuthenticationOptions Replay(ServiceDescriptor[] configurers)
    {
        var observed = new AuthenticationOptions();

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

            configurer.Configure(observed);
        }

        return observed;
    }

    /// <summary>
    /// A configurer in the window that also set a default belongs on <c>AddAuthentication</c>:
    /// removing the descriptor would silently discard the default, and keeping it would put the
    /// provider scheme in the host's map.
    /// </summary>
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
