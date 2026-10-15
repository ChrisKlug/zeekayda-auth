using System.Collections.Concurrent;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Where <see cref="HandlerOptionsValidator{TOptions}"/> records its pin findings for
/// <see cref="HandlerOptionsActivator"/>, since an <c>OptionsValidationException</c> cannot say who wrote what.
/// </summary>
/// <remarks>
/// Keyed by options type as well as name, since a host validator may resolve another options type under
/// the same name mid-build. A concurrent resolution between clear and read can misattribute the
/// diagnosis, never leak text; accepted, since startup fails closed either way.
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
