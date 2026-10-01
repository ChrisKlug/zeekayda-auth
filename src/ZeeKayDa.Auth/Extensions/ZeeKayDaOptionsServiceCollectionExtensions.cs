using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers options that ZeeKayDa.Auth validates together, so that the operator sees every
/// failure across them in one <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <remarks>
/// <para>
/// The framework registers all of its own options this way, and a package that extends it (a
/// signing-key source, for example) should do the same instead of calling <c>ValidateOnStart()</c>.
/// The options are validated when <c>MapZeeKayDaAuth()</c> runs, and again when the host starts for
/// a host that never maps the endpoints, by the startup gate <c>AddZeeKayDaAuthCore()</c> registers.
/// </para>
/// <para>
/// For its failures to carry codes, a validator derives from
/// <see cref="ZeeKayDaOptionsValidator{TOptions}"/>. Any other <see cref="IValidateOptions{TOptions}"/>
/// still takes part, reported as one <c>configuration.options_invalid</c> failure naming the options
/// type, with its messages in the inner exception.
/// </para>
/// </remarks>
public static class ZeeKayDaOptionsServiceCollectionExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TOptions"/> and validates it with every other options type
    /// registered through ZeeKayDa.Auth.
    /// </summary>
    /// <typeparam name="TOptions">The options type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The options builder, for further configuration.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/>.</exception>
    public static OptionsBuilder<TOptions> AddZeeKayDaOptions<TOptions>(this IServiceCollection services)
        where TOptions : class =>
        services.AddOptions<TOptions>().ValidateWithZeeKayDa();

    /// <summary>
    /// Validates the options this builder configures with every other options type registered
    /// through ZeeKayDa.Auth, in place of <c>ValidateOnStart()</c>.
    /// </summary>
    /// <typeparam name="TOptions">The options type.</typeparam>
    /// <param name="builder">The options builder.</param>
    /// <returns>The same builder.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is <see langword="null"/>.</exception>
    public static OptionsBuilder<TOptions> ValidateWithZeeKayDa<TOptions>(this OptionsBuilder<TOptions> builder)
        where TOptions : class
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new ValidatedOptions<TOptions>(builder.Name);
        if (!builder.Services.Any(descriptor => Equals(descriptor.ImplementationInstance, options)))
            builder.Services.AddSingleton<IValidatedOptions>(options);

        return builder;
    }
}
