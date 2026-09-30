using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Freezes the collections on <see cref="AuthorizationServerOptions"/> and its groups once
/// configuration has finished, so nothing can change what startup validation approved.
/// </summary>
internal static class FrozenOptions
{
    /// <summary>A read-only copy of the host's values, in the host's order; null stays null.</summary>
    [return: NotNullIfNotNull(nameof(values))]
    public static ReadOnlyCollection<T>? Copy<T>(ICollection<T>? values) => values?.ToList().AsReadOnly();

    /// <summary>
    /// The value to assign, or a failure when the options are frozen: a collection replaced after
    /// validation would never be checked.
    /// </summary>
    public static T Assign<T>(bool frozen, T value, string property) =>
        frozen
            ? throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "configuration.options_frozen",
                $"{property} cannot be replaced once configuration has finished. Set it in the configure " +
                "callback passed to AddZeeKayDaAuth, or with Configure<AuthorizationServerOptions>."))
            : value;
}
