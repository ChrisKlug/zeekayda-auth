using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Configuration;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers options that ZeeKayDa.Auth validates together, so the operator sees every failure in
/// one <see cref="ZeeKayDaConfigurationException"/>. An extension package uses this instead of <c>ValidateOnStart()</c>.
/// </summary>
/// <remarks>
/// A validator deriving from <see cref="ZeeKayDaOptionsValidator{TOptions}"/> reports coded failures;
/// any other <see cref="IValidateOptions{TOptions}"/> is reported as one <c>configuration.options_invalid</c>.
/// </remarks>
public static class ZeeKayDaOptionsServiceCollectionExtensions
{
    /// <summary>Registers <typeparamref name="TOptions"/> for validation with the other ZeeKayDa.Auth options.</summary>
    /// <typeparam name="TOptions">The options type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The options builder, for further configuration.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/>.</exception>
    public static OptionsBuilder<TOptions> AddZeeKayDaOptions<TOptions>(this IServiceCollection services)
        where TOptions : class =>
        services.AddOptions<TOptions>().ValidateWithZeeKayDa();

    /// <summary>Validates these options with the other ZeeKayDa.Auth options, in place of <c>ValidateOnStart()</c>.</summary>
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
