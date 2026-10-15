namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// One failed pin assertion: the member the framework owns and the value it requires
/// (<see langword="null"/>: unset). Provenance is the type, never a marker inside a string.
/// </summary>
internal sealed record PinnedOptionDrift(string Member, string? Expected)
{
    /// <summary>The framework's sentence for this drift, shared by the validator and the startup failure.</summary>
    public string Describe() => Expected is null
        ? $"{Member} must not be set."
        : $"{Member} must be '{Expected}'.";
}
