namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// One framework-owned pin assertion that failed: the provider whose options drifted, the member
/// the framework owns, and the value it requires (<see langword="null"/> when the member must
/// simply not be set).
/// </summary>
/// <remarks>
/// This exists so that provenance is carried by a type only the framework can produce, rather than
/// by a marker inside a string. <see cref="HandlerOptionsValidator{TOptions}"/> must hand its
/// findings to <c>Microsoft.Extensions.Options</c> as plain strings — that is
/// <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/>'s contract — and those
/// strings land in one flat <see cref="Microsoft.Extensions.Options.OptionsValidationException.Failures"/>
/// list alongside every other validator's. Recovering "which of these did the framework write?"
/// from that list by testing for a prefix is not a provenance check at all: a provider or host
/// validator is free to return a string beginning with the same characters. Every field here is
/// framework-owned, so the message composed from it is too.
/// </remarks>
internal sealed record PinnedOptionDrift(string Member, string? Expected)
{
    /// <summary>
    /// The framework's own sentence for this drift. Both the validator's failure string and the
    /// startup failure's message are built from this, so the two can never disagree.
    /// </summary>
    public string Describe() => Expected is null
        ? $"{Member} must not be set."
        : $"{Member} must be '{Expected}'.";
}
