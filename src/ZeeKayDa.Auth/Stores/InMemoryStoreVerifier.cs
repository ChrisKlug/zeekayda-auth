using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Reports at startup that an in-memory store is active, losing its contents on restart and invisible to
/// other instances; <see cref="EnvironmentGate"/> decides whether that is allowed.
/// </summary>
/// <remarks>
/// One instance per in-memory store, added with plain <c>AddScoped</c> since <c>TryAddEnumerable</c> would
/// deduplicate them.
/// </remarks>
internal sealed class InMemoryStoreVerifier(
    IHostEnvironment environment,
    string storeName,
    bool allowOutsideDevelopment) : IStartupVerifier
{
    /// <summary>The store name passed for the authorization code store registration.</summary>
    internal const string AuthorizationCodeStoreName = "authorization code store";

    /// <summary>The store name passed for the refresh token store registration.</summary>
    internal const string RefreshTokenStoreName = "refresh token store";

    /// <summary>The store name passed for the interaction store registration.</summary>
    internal const string InteractionStoreName = "interaction store";

    /// <summary>Named-placeholder template for the Development startup message.</summary>
    internal const string ActiveMessageFormat =
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

    /// <inheritdoc/>
    public string Name => $"InMemoryStore({storeName})";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        switch (EnvironmentGate.Evaluate(environment, allowOutsideDevelopment))
        {
            case EnvironmentGate.Verdict.ExpectedInDevelopment:
                context.AddWarning("stores.inmemory.active", ActiveMessageFormat, LogLevel.Information, storeName);
                break;

            case EnvironmentGate.Verdict.AllowedByOptOut:
                context.AddWarning(
                    "stores.inmemory.non_development_override",
                    NonDevelopmentOverrideWarningMessageFormat,
                    LogLevel.Critical,
                    storeName);
                break;

            default:
                // Names its store: the runner collapses identical failures, which would hide all but one.
                context.AddFailure(
                    "stores.inmemory.non_development",
                    $"The in-memory {storeName} is active outside a Development environment. " +
                    "This is a configuration error: in-memory stores lose their contents on restart " +
                    "and are invisible to other instances. " +
                    "Replace this registration with a persistent store implementation, or pass " +
                    "allowOutsideDevelopment: true if this host is an intentional " +
                    "non-Development test host.");
                break;
        }

        return Task.CompletedTask;
    }
}
