using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when an in-memory store is active, alerting operators that its
/// contents are lost on process restart and invisible to other instances — tokens, single-use
/// enforcement and reuse detection for the token stores, in-flight authorization requests for the
/// interaction store.
/// </summary>
/// <remarks>
/// One instance is registered per in-memory store registration call, each capturing its own
/// <c>storeName</c> and <c>allowOutsideDevelopment</c> value, so the gate is enforced
/// independently per store. Outside <c>Development</c>, startup fails unless the captured
/// <c>allowOutsideDevelopment</c> is <see langword="true"/>. The registrations share this
/// implementation type but are added via plain <c>AddSingleton&lt;IStartupVerifier&gt;</c> rather
/// than <c>TryAddEnumerable</c>, which would otherwise deduplicate them away.
/// </remarks>
internal sealed class InMemoryStoreVerifier : IStartupVerifier
{
    /// <summary>The store name passed for the authorization code store registration.</summary>
    internal const string AuthorizationCodeStoreName = "authorization code store";

    /// <summary>The store name passed for the refresh token store registration.</summary>
    internal const string RefreshTokenStoreName = "refresh token store";

    /// <summary>The store name passed for the interaction store registration.</summary>
    internal const string InteractionStoreName = "interaction store";

    /// <summary>Named-placeholder template for the mandatory startup warning.</summary>
    internal const string WarningMessageFormat =
        "ZeeKayDa.Auth: the in-memory {StoreName} is active. Its contents are lost on process " +
        "restart and invisible to other instances: issued tokens, single-use enforcement and reuse " +
        "detection do not survive a restart or span a multi-instance deployment, and an in-flight " +
        "authorization request cannot be completed by another instance. This configuration is " +
        "intended for development and testing only and must not be used in production.";

    /// <summary>Named-placeholder template for the non-Development override warning.</summary>
    internal const string NonDevelopmentOverrideWarningMessageFormat =
        "ZeeKayDa.Auth: the in-memory {StoreName} is active outside a Development environment. " +
        "allowOutsideDevelopment has been set to true for this registration — ensure this is " +
        "intentional (e.g. an integration test host). Do not use in-memory stores in production.";

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
    /// Every <see cref="InMemoryStoreVerifier"/> instance shares the category
    /// <see cref="InMemoryStoreVerifier"/> — this instance <see cref="Name"/> (e.g.
    /// <c>InMemoryStore(authorization code store)</c>) is what still lets an operator or log query
    /// tell the registrations apart.
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
            // Names its own store: one instance is registered per in-memory store, all report in
            // the same phase, and the runner collapses failures that are identical in code and
            // message — so a message naming no store would report one of several broken
            // registrations and send the operator round the restart cycle for the others.
            context.AddFailure(
                "stores.inmemory.non_development",
                $"The in-memory {_storeName} is active outside a Development environment. " +
                "This is a configuration error: in-memory stores lose their contents on restart " +
                "and are invisible to other instances. " +
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
