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
/// cache a failed options build — so a record always replaces the previous one rather than
/// accumulating, and a validating run that finds nothing records an empty list so a stale finding
/// can never outlive the drift that produced it.
/// </para>
/// <para>
/// <strong>Keyed by options type as well as provider name, and cleared before the attempt it
/// describes.</strong> The validator is registered open-generic, so it runs for every options type
/// resolved under a name the provider registry knows — a host validator is free to resolve a
/// second <see cref="Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions"/> subtype
/// under that same name while the first is still being built. Keyed by name alone, that inner
/// resolution would overwrite the outer one's findings, and the activator would report one options
/// type's pin assertions as belonging to another. The clear scopes the read to the attempt: a
/// resolution that throws before this validator runs reports no pin assertions rather than a
/// previous attempt's.
/// </para>
/// <para>
/// <strong>The bound on that, stated rather than engineered away:</strong> a resolution of the same
/// name and options type running concurrently — a host hosted service started alongside the runner
/// under <c>HostOptions.ServicesStartConcurrently</c> — can write between the clear and the read,
/// because <see cref="ConcurrentDictionary{TKey, TValue}"/> makes each operation atomic and nothing
/// more. It would write the findings of the same validator against the same named options, so in
/// practice it writes what was already there; the case where it does not is a host reconfiguring
/// those options mid-startup. Accepted rather than serialized: the consequence is a misattributed
/// or absent *diagnosis*, never leaked text — a recorded drift holds only a framework-chosen member
/// name and the framework's own expected value — and startup fails closed on the underlying
/// exception either way. Correlating each record with its resolution needs an execution-flow
/// context threaded through <c>Microsoft.Extensions.Options</c>, which is more machinery than the
/// accuracy of one startup message is worth.
/// </para>
/// </remarks>
internal sealed class PinnedOptionDriftRecorder
{
    private readonly ConcurrentDictionary<(string Provider, Type Options), IReadOnlyList<PinnedOptionDrift>> _drifts =
        new();

    public void Record(string providerName, Type optionsType, IReadOnlyList<PinnedOptionDrift> drifts)
        => _drifts[(providerName, optionsType)] = drifts;

    /// <summary>Discards any previous finding, so the next read describes only the attempt that follows.</summary>
    public void Clear(string providerName, Type optionsType)
        => _drifts.TryRemove((providerName, optionsType), out _);

    public IReadOnlyList<PinnedOptionDrift> DriftsFor(string providerName, Type optionsType)
        => _drifts.TryGetValue((providerName, optionsType), out var drifts) ? drifts : [];
}
