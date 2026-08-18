using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when an in-memory token store is active, alerting operators that
/// tokens will be lost on process restart and that single-use enforcement and reuse detection
/// are disabled across multiple instances.
/// </summary>
/// <remarks>
/// One instance is registered per in-memory store registration call, each capturing its own
/// <c>storeName</c> and <c>allowOutsideDevelopment</c> value, so the gate is enforced
/// independently per store. Outside <c>Development</c>, startup fails unless the captured
/// <c>allowOutsideDevelopment</c> is <see langword="true"/>. Both registrations share this
/// implementation type but are added via plain <c>AddSingleton&lt;IStartupVerifier&gt;</c> rather
/// than <c>TryAddEnumerable</c>, which would otherwise deduplicate the two registrations away.
/// </remarks>
internal sealed class InMemoryStoreVerifier : IStartupVerifier
{
    /// <summary>The store name passed for the authorization code store registration.</summary>
    internal const string AuthorizationCodeStoreName = "authorization code store";

    /// <summary>The store name passed for the refresh token store registration.</summary>
    internal const string RefreshTokenStoreName = "refresh token store";

    /// <summary>Named-placeholder template for the mandatory startup warning.</summary>
    internal const string WarningMessageFormat =
        "ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on " +
        "process restart, and single-use enforcement and reuse detection are disabled across " +
        "multiple instances. This configuration is intended for development and testing only " +
        "and must not be used in production. Store: {StoreName}.";

    /// <summary>Named-placeholder template for the non-Development override warning.</summary>
    internal const string NonDevelopmentOverrideWarningMessageFormat =
        "ZeeKayDa.Auth: in-memory token stores are active outside a Development environment. " +
        "allowOutsideDevelopment has been set to true for this registration ({StoreName}) — ensure " +
        "this is intentional (e.g. an integration test host). Do not use in-memory stores in " +
        "production.";

    private readonly IHostEnvironment _environment;
    private readonly string _storeName;
    private readonly bool _allowOutsideDevelopment;

    public InMemoryStoreVerifier(
        IHostEnvironment environment,
        string storeName,
        bool allowOutsideDevelopment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeName);

        _environment = environment;
        _storeName = storeName;
        _allowOutsideDevelopment = allowOutsideDevelopment;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Both <see cref="InMemoryStoreVerifier"/> instances share the category
    /// <see cref="InMemoryStoreVerifier"/> — this instance <see cref="Name"/> (e.g.
    /// <c>InMemoryStore(authorization code store)</c>) is what still lets an operator or log query
    /// tell the two registrations apart.
    /// </remarks>
    public string Name => $"InMemoryStore({_storeName})";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (_environment.IsDevelopment())
        {
            context.AddWarning("stores.inmemory.active", WarningMessageFormat, _storeName);
            return ValueTask.CompletedTask;
        }

        if (!_allowOutsideDevelopment)
        {
            context.AddFailure(
                "stores.inmemory.non_development",
                "In-memory token stores are active outside a Development environment. " +
                "This is a configuration error: in-memory stores lose all tokens on restart " +
                "and disable single-use enforcement across instances. " +
                "Replace this registration with a persistent store implementation, or pass " +
                "allowOutsideDevelopment: true if this host is an intentional " +
                "non-Development test host.");
            return ValueTask.CompletedTask;
        }

        context.AddWarning(
            "stores.inmemory.non_development_override",
            NonDevelopmentOverrideWarningMessageFormat,
            LogLevel.Critical,
            _storeName);

        return ValueTask.CompletedTask;
    }
}
