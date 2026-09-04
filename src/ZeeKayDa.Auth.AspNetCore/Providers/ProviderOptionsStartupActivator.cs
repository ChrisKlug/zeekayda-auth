using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Resolves each registered provider's options once at startup, so that a provider whose options
/// fail validation — its own rules, or the framework's pins asserted by
/// <see cref="ProviderOptionsValidator{TOptions}"/> — fails the application before its first
/// sign-in rather than during it.
/// </summary>
/// <remarks>
/// An activator rather than a verifier, by the mechanical rule: resolving the options runs the
/// provider's and the host's own configuration code. The options type is read off the handler's
/// base chain, once, here; nothing on the request path uses reflection. A handler that does not
/// derive from <see cref="RemoteAuthenticationHandler{TOptions}"/> has no options object to pin,
/// so there is nothing to assert for it.
/// </remarks>
internal sealed class ProviderOptionsStartupActivator : IStartupActivator
{
    private readonly ProviderRegistry _registry;

    public ProviderOptionsStartupActivator(ProviderRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        _registry = registry;
    }

    /// <inheritdoc/>
    public string Name => "ProviderOptions";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(scopedServices);

        foreach (var registration in _registry.Registrations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (RemoteOptionsType(registration.HandlerType) is not { } optionsType)
                continue;

            try
            {
                OptionsResolver.For(optionsType).Resolve(scopedServices, registration.Name);
            }
            catch (OptionsValidationException ex)
            {
                context.AddFailure(
                    "provider.options_invalid",
                    $"The options for provider '{registration.Name}' are not valid: {string.Join(" ", ex.Failures)}");
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The <c>TOptions</c> of the <see cref="RemoteAuthenticationHandler{TOptions}"/> in the
    /// handler's base chain, or <see langword="null"/> for a handler outside that hierarchy.
    /// </summary>
    private static Type? RemoteOptionsType(Type handlerType)
    {
        for (var type = handlerType; type is not null; type = type.BaseType)
        {
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(RemoteAuthenticationHandler<>))
                return type.GenericTypeArguments[0];
        }

        return null;
    }

    /// <summary>
    /// Resolves <c>IOptionsMonitor&lt;TOptions&gt;</c> for an options type known only at runtime,
    /// through a virtual call rather than a reflective invoke, so a validation failure surfaces as
    /// itself and not wrapped in a <see cref="System.Reflection.TargetInvocationException"/>.
    /// </summary>
    private abstract class OptionsResolver
    {
        public static OptionsResolver For(Type optionsType) =>
            (OptionsResolver)Activator.CreateInstance(typeof(OptionsResolver<>).MakeGenericType(optionsType))!;

        public abstract void Resolve(IServiceProvider services, string name);
    }

    private sealed class OptionsResolver<TOptions> : OptionsResolver
        where TOptions : class
    {
        public override void Resolve(IServiceProvider services, string name) =>
            services.GetRequiredService<IOptionsMonitor<TOptions>>().Get(name);
    }
}
