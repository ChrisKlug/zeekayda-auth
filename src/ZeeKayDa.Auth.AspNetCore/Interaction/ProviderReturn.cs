namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A provider trip that brought the user back to the login page instead of signing them in,
/// recorded from the callback, never from the request.
/// </summary>
public sealed class ProviderReturn
{
    internal ProviderReturn(ProviderDescriptor provider, ProviderReturnOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(provider);

        Provider = provider;
        Outcome = outcome;
    }

    /// <summary>The provider the user came back from — the same descriptor as in <see cref="LoginRequest.Providers"/>.</summary>
    public ProviderDescriptor Provider { get; }

    /// <summary>How the trip ended.</summary>
    public ProviderReturnOutcome Outcome { get; }
}

/// <summary>How a trip to an external provider ended when it did not sign the user in.</summary>
public enum ProviderReturnOutcome
{
    /// <summary>The user cancelled, or refused, at the provider.</summary>
    Declined,

    /// <summary>The provider's callback failed — an error at the provider, or a response the framework could not complete.</summary>
    Failed,
}
