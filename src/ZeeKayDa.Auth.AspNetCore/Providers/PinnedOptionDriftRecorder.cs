using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The side channel <see cref="HandlerOptionsValidator{TOptions}"/> writes its structured pin
/// findings to, and <see cref="HandlerOptionsStartupActivator"/> reads them back from.
/// </summary>
/// <remarks>
/// <para>
/// The activator learns that validation failed by catching
/// <see cref="Microsoft.Extensions.Options.OptionsValidationException"/>, which carries only
/// strings and cannot say who wrote them. It therefore asks this recorder what the framework
/// itself found, instead of trying to recognise the framework's own text in that list. Anything it
/// does not find here came from somebody else's validator and is counted, never quoted.
/// </para>
/// <para>
/// A singleton, because the validator is registered as one. Validation for a given name runs again
/// on every resolve once it has failed — <c>Microsoft.Extensions.DependencyInjection</c> does not
/// cache a failed options build — so a record always replaces the previous one for that name
/// rather than accumulating, and a validating run that finds nothing records an empty list so a
/// stale finding can never outlive the drift that produced it.
/// </para>
/// </remarks>
internal sealed class PinnedOptionDriftRecorder
{
    private readonly ConcurrentDictionary<string, IReadOnlyList<PinnedOptionDrift>> _byProvider =
        new(StringComparer.Ordinal);

    public void Record(string providerName, IReadOnlyList<PinnedOptionDrift> drifts)
        => _byProvider[providerName] = drifts;

    public IReadOnlyList<PinnedOptionDrift> DriftsFor(string providerName)
        => _byProvider.TryGetValue(providerName, out var drifts) ? drifts : [];
}
