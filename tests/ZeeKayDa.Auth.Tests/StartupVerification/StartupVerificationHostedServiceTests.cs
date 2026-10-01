using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.StartupVerification;

/// <summary>
/// Exercises <see cref="StartupVerificationHostedService"/>'s two-phase <c>StartAsync</c>: each
/// phase's run-all-then-aggregate semantics, one scope per phase, the unexpected-exception special
/// cases, and that a warning's structured arguments still reach <c>SanitizingLogger</c>'s by-key
/// redaction after being composed with the runner's own constant prefix.
/// </summary>
public sealed class StartupVerificationHostedServiceTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    /// <summary>Shared sink for <see cref="CapturingLogger{T}"/>, keyed by the closed generic type
    /// the reflective <c>SanitizingLogger&lt;&gt;</c> resolution was made against.</summary>
    private sealed class LogSink
    {
        public sealed record Entry(Type Category, LogLevel Level, IReadOnlyList<KeyValuePair<string, object?>> Pairs);

        public List<Entry> Entries { get; } = [];
    }

    private sealed class CapturingLogger<T>(LogSink sink) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var pairs = state is IEnumerable<KeyValuePair<string, object?>> kvps ? kvps.ToList() : [];
            sink.Entries.Add(new LogSink.Entry(typeof(T), logLevel, pairs));
        }
    }

    private sealed class DelegatingVerifier(string name, Func<StartupVerificationContext, Task> act) : IStartupVerifier
    {
        public string Name => name;

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
            => act(context);
    }

    private sealed class DelegatingActivator(string name, Func<StartupVerificationContext, Task> act) : IStartupActivator
    {
        public string Name => name;

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
            => act(context);
    }

    private static ServiceProvider BuildProviderWithSanitizingLogging(
        out LogSink sink, Action<ServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        var localSink = new LogSink();
        services.AddSingleton(localSink);
        services.AddSingleton(typeof(ILogger<>), typeof(CapturingLogger<>));
        services.AddSingleton(typeof(SanitizingLogger<>), typeof(RegisteredSanitizingLogger<>));
        services.AddSingleton<IOptions<AuthorizationServerOptions>>(Options.Create(new AuthorizationServerOptions()));
        configure?.Invoke(services);

        var provider = services.BuildServiceProvider();
        sink = localSink;
        return provider;
    }

    // ── Redaction survives the runner's template composition (issue #444) ──────────────────────────

    [Fact]
    public async Task StartAsync_logs_a_verifier_warning_under_the_verifiers_own_type_with_the_composed_template_and_redacted_secret()
    {
        var verifier = new DelegatingVerifier("RedactionProbe", context =>
        {
            context.AddWarning("x.code", "value {client_secret}", "s3cr3t-value");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(
            out var sink, services => services.AddSingleton<IStartupVerifier>(verifier));

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        var entry = sink.Entries.Should().ContainSingle().Subject;
        entry.Category.Should().Be(verifier.GetType(), "the log category must be the verifier's own runtime type, not the runner's");
        entry.Pairs.Should().Contain(kv =>
            kv.Key == "{OriginalFormat}" && (string?)kv.Value == "[{Verifier}] {ErrorCode}: value {client_secret}");
        entry.Pairs.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
        entry.Pairs.Should().Contain(kv => kv.Key == "Verifier" && (string?)kv.Value == "RedactionProbe");

        // The runner's own placeholder is named {ErrorCode}, not {Code}, so it does not collide
        // with SanitizingLogger.SensitiveKeys' "code" entry: the warning's stable
        // discriminator survives redaction untouched, as the design requires.
        entry.Pairs.Should().Contain(kv => kv.Key == "ErrorCode" && (string?)kv.Value == "x.code");
    }

    [Fact]
    public async Task StartAsync_reports_a_verifier_warning_that_fails_to_log_as_an_aggregated_failure()
    {
        // A template placeholder with no matching arg throws from inside the logging framework's
        // own state formatter, not from VerifyAsync — this must not crash StartAsync unattributed
        // or discard an already-aggregated genuine configuration failure.
        var badVerifier = new DelegatingVerifier("BadWarningVerifier", context =>
        {
            context.AddWarning("bad.warning", "value {missing}");
            return Task.CompletedTask;
        });
        var goodVerifier = new DelegatingVerifier("GoodVerifier", context =>
        {
            context.AddFailure("real.failure", "a genuine configuration problem");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(
            out _,
            services =>
            {
                services.AddSingleton<IStartupVerifier>(badVerifier);
                services.AddSingleton<IStartupVerifier>(goodVerifier);
            });

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().Contain(f => f.Code == "startup.warning_log_failed");
        exception.Which.AggregatedFailures.Should().Contain(
            f => f.Code == "real.failure",
            "a warning that fails to log must not discard an already-aggregated genuine configuration failure");
    }

    // ── Aggregation semantics: run all, aggregate, throw once ───────────────────────────────

    [Fact]
    public async Task StartAsync_runs_every_verifier_and_aggregates_all_failures_into_one_exception()
    {
        var verifier1Ran = false;
        var verifier2Ran = false;
        var verifier1 = new DelegatingVerifier("V1", context =>
        {
            verifier1Ran = true;
            context.AddFailure("v1.fail", "first failure");
            return Task.CompletedTask;
        });
        var verifier2 = new DelegatingVerifier("V2", context =>
        {
            verifier2Ran = true;
            context.AddFailure("v2.fail", "second failure");
            return Task.CompletedTask;
        });

        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(verifier1);
        services.AddSingleton<IStartupVerifier>(verifier2);
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        verifier1Ran.Should().BeTrue();
        verifier2Ran.Should().BeTrue("every verifier must run regardless of an earlier one having failed");
        exception.Which.AggregatedFailures.Select(f => f.Code).Should().BeEquivalentTo("v1.fail", "v2.fail");
    }

    // ── Unexpected-exception handling ────────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAsync_unwraps_a_ZeeKayDaConfigurationException_thrown_by_a_verifier_preserving_its_codes()
    {
        var services = new ServiceCollection();
        var thrown = new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure("signing.self_test_failed", "boom"));
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("V", _ => throw thrown));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("signing.self_test_failed");
    }

    // A failure message that says "See the inner exception for the root cause" — the convention the
    // Key Vault readers follow — must resolve to that root cause after the runner has absorbed the
    // codes, not to nothing (#618).
    [Fact]
    public async Task StartAsync_preserves_the_root_cause_of_an_absorbed_ZeeKayDaConfigurationException()
    {
        var rootCause = new UnauthorizedAccessException("denied");
        var thrown = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("keyvault.read_failed", "See the inner exception."), rootCause);
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("V", _ => throw thrown));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("keyvault.read_failed");
        exception.Which.InnerException.Should().BeSameAs(rootCause);
    }

    [Fact]
    public async Task StartAsync_leaves_the_aggregate_without_an_inner_exception_when_the_absorbed_exception_had_none()
    {
        var thrown = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.self_test_failed", "boom"));
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("V", _ => throw thrown));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.InnerException.Should().BeNull(
            "a configuration exception with no root cause behind it contributes nothing to carry");
    }

    [Fact]
    public async Task StartAsync_wraps_an_absorbed_root_cause_and_an_unexpected_throw_in_one_AggregateException()
    {
        var rootCause = new UnauthorizedAccessException("denied");
        var absorbed = new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("keyvault.read_failed", "See the inner exception."), rootCause);
        var unexpected = new InvalidOperationException("boom");
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("Absorbed", _ => throw absorbed));
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("Unexpected", _ => throw unexpected));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        var causes = exception.Which.InnerException.Should().BeOfType<AggregateException>().Which.InnerExceptions;
        causes.Should().HaveCount(2);
        causes.Should().Contain(rootCause).And.Contain(unexpected);
    }

    [Fact]
    public async Task StartAsync_rethrows_OperationCanceledException_unchanged_when_the_token_is_signalled()
    {
        using var cts = new CancellationTokenSource();
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("V", _ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        }));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task StartAsync_wraps_an_unexpected_exception_naming_only_the_exception_type_never_its_message()
    {
        var services = new ServiceCollection();
        const string secretLadenMessage = "connection string contains password=hunter2";
        services.AddSingleton<IStartupVerifier>(new DelegatingVerifier(
            "V", _ => throw new InvalidOperationException(secretLadenMessage)));
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        var failure = exception.Which.AggregatedFailures.Should().ContainSingle().Subject;
        failure.Code.Should().Be("startup.verifier_failed");
        failure.Message.Should().Contain(typeof(InvalidOperationException).FullName!);
        failure.Message.Should().NotContain(secretLadenMessage);
        exception.Which.InnerException.Should().BeOfType<InvalidOperationException>();
    }

    // ── Phase separation: activators do not run when a verifier failed (#499) ────────────────────

    [Fact]
    public async Task StartAsync_does_not_run_activators_when_a_verifier_failed()
    {
        // The point of the phase: an application with a broken issuer must not open a remote
        // connection to a key vault before it is told about the issuer.
        var activatorRan = false;
        var verifier = new DelegatingVerifier("Cheap", context =>
        {
            context.AddFailure("config.broken", "Simulated cheap failure.");
            return Task.CompletedTask;
        });
        var activator = new DelegatingActivator("Expensive", _ =>
        {
            activatorRan = true;
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(verifier);
            services.AddSingleton<IStartupActivator>(activator);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("config.broken");
        activatorRan.Should().BeFalse();
    }

    [Fact]
    public async Task StartAsync_runs_activators_when_every_verifier_passed()
    {
        var activatorRan = false;
        var verifier = new DelegatingVerifier("Cheap", _ => Task.CompletedTask);
        var activator = new DelegatingActivator("Expensive", _ =>
        {
            activatorRan = true;
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(verifier);
            services.AddSingleton<IStartupActivator>(activator);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        activatorRan.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_aggregates_activator_failures_across_the_whole_activator_phase()
    {
        var first = new DelegatingActivator("First", context =>
        {
            context.AddFailure("first.failed", "First.");
            return Task.CompletedTask;
        });
        var second = new DelegatingActivator("Second", context =>
        {
            context.AddFailure("second.failed", "Second.");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupActivator>(first);
            services.AddSingleton<IStartupActivator>(second);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().HaveCount(2);
    }

    // ── A throwing check must not discard the aggregate (#500) ───────────────────────────────────

    [Fact]
    public async Task StartAsync_keeps_every_aggregated_failure_when_a_later_check_throws_unexpectedly()
    {
        // Three genuine, fixable errors plus one check with a bug used to surface as the bug alone,
        // sending the operator round the fix-and-restart cycle aggregation exists to prevent.
        var failing = new DelegatingVerifier("Failing", context =>
        {
            context.AddFailure("genuine.one", "One.");
            context.AddFailure("genuine.two", "Two.");
            return Task.CompletedTask;
        });
        var throwing = new DelegatingVerifier("Throwing", _ => throw new InvalidOperationException("boom"));
        var later = new DelegatingVerifier("Later", context =>
        {
            context.AddFailure("genuine.three", "Three.");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(failing);
            services.AddSingleton<IStartupVerifier>(throwing);
            services.AddSingleton<IStartupVerifier>(later);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Select(f => f.Code).Should().BeEquivalentTo(
            ["genuine.one", "genuine.two", "startup.verifier_failed", "genuine.three"],
            "checks after the throwing one still run, and nothing already reported is discarded");
    }

    [Fact]
    public async Task StartAsync_preserves_an_unexpected_exception_as_the_aggregates_inner_exception()
    {
        var throwing = new DelegatingVerifier("Throwing", _ => throw new InvalidOperationException("boom"));
        var failing = new DelegatingVerifier("Failing", context =>
        {
            context.AddFailure("genuine.one", "One.");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(throwing);
            services.AddSingleton<IStartupVerifier>(failing);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.InnerException.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be("boom");
    }

    [Fact]
    public async Task StartAsync_wraps_several_unexpected_exceptions_in_one_AggregateException()
    {
        var firstThrow = new DelegatingVerifier("One", _ => throw new InvalidOperationException("first"));
        var secondThrow = new DelegatingVerifier("Two", _ => throw new NotSupportedException("second"));
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(firstThrow);
            services.AddSingleton<IStartupVerifier>(secondThrow);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Should().HaveCount(2);
        ex.InnerException.Should().BeOfType<AggregateException>()
            .Which.InnerExceptions.Should().HaveCount(2);
    }

    [Fact]
    public async Task StartAsync_collapses_identical_failures_reported_by_two_checks_in_one_phase()
    {
        // Two checks that both need the signing key set both report its failure, because each
        // genuinely needs it initialized. That is one broken configuration, not two problems.
        var first = new DelegatingActivator("First", context =>
        {
            context.AddFailure("signing.source_unavailable", "The source refused.");
            return Task.CompletedTask;
        });
        var second = new DelegatingActivator("Second", context =>
        {
            context.AddFailure("signing.source_unavailable", "The source refused.");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupActivator>(first);
            services.AddSingleton<IStartupActivator>(second);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle();
    }

    [Fact]
    public async Task StartAsync_keeps_two_failures_that_share_a_code_but_not_a_message()
    {
        // Same code, different subject — two clients, two stores — is two problems.
        var first = new DelegatingVerifier("First", context =>
        {
            context.AddFailure("client.invalid", "Client 'a' is invalid.");
            return Task.CompletedTask;
        });
        var second = new DelegatingVerifier("Second", context =>
        {
            context.AddFailure("client.invalid", "Client 'b' is invalid.");
            return Task.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(first);
            services.AddSingleton<IStartupVerifier>(second);
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().HaveCount(2);
    }

    [Fact]
    public async Task StartAsync_keeps_the_root_cause_of_a_failure_collapsed_as_a_duplicate()
    {
        var firstCause = new UnauthorizedAccessException("first");
        var secondCause = new TimeoutException("second");
        var failure = new ZeeKayDaConfigurationFailure("signing.source_unavailable", "The source refused.");
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupActivator>(new DelegatingActivator(
                "First", _ => throw new ZeeKayDaConfigurationException(failure, firstCause)));
            services.AddSingleton<IStartupActivator>(new DelegatingActivator(
                "Second", _ => throw new ZeeKayDaConfigurationException(failure, secondCause)));
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Should().ContainSingle();
        ex.InnerException.Should().BeOfType<AggregateException>()
            .Which.InnerExceptions.Should().HaveCount(2).And.Contain(firstCause).And.Contain(secondCause);
    }

    [Fact]
    public async Task StartAsync_carries_the_root_cause_of_a_warning_that_failed_to_log()
    {
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
            services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("BadWarning", context =>
            {
                context.AddWarning("bad.warning", "value {missing}");
                return Task.CompletedTask;
            })));
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("startup.warning_log_failed");
        ex.InnerException.Should().NotBeNull("the failure's message points the reader at the inner exception");
    }

    [Fact]
    public async Task StartAsync_logs_every_warning_in_a_phase_before_throwing_its_failures()
    {
        using var provider = BuildProviderWithSanitizingLogging(out var sink, services =>
        {
            services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("Failing", context =>
            {
                context.AddFailure("config.broken", "Broken.");
                return Task.CompletedTask;
            }));
            services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("Warning", context =>
            {
                context.AddWarning("config.odd", "Odd.");
                return Task.CompletedTask;
            }));
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        sink.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Warning);
    }

    // ── Checks are constructor-injected, from one scope per phase ────────────────────────────────

    private sealed class ScopedMarker;

    private sealed class MarkerVerifier(ScopedMarker marker, List<ScopedMarker> seen) : IStartupVerifier
    {
        public string Name => "Marker";

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
        {
            seen.Add(marker);
            return Task.CompletedTask;
        }
    }

    private sealed class MarkerActivator(ScopedMarker marker, List<ScopedMarker> seen) : IStartupActivator
    {
        public string Name => "Marker";

        public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
        {
            seen.Add(marker);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task StartAsync_resolves_the_checks_in_a_phase_from_one_scope_and_each_phase_from_its_own()
    {
        var verifierScopes = new List<ScopedMarker>();
        var activatorScopes = new List<ScopedMarker>();
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddScoped<ScopedMarker>();
            services.AddScoped<IStartupVerifier>(sp => new MarkerVerifier(sp.GetRequiredService<ScopedMarker>(), verifierScopes));
            services.AddScoped<IStartupVerifier>(sp => new MarkerVerifier(sp.GetRequiredService<ScopedMarker>(), verifierScopes));
            services.AddScoped<IStartupActivator>(sp => new MarkerActivator(sp.GetRequiredService<ScopedMarker>(), activatorScopes));
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        verifierScopes.Should().HaveCount(2).And.OnlyContain(marker => marker == verifierScopes[0]);
        activatorScopes.Should().ContainSingle().Which.Should().NotBeSameAs(verifierScopes[0]);
    }

    [Fact]
    public async Task StartAsync_does_not_construct_activators_when_a_verifier_failed()
    {
        var activatorConstructed = false;
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(new DelegatingVerifier("Cheap", context =>
            {
                context.AddFailure("config.broken", "Broken.");
                return Task.CompletedTask;
            }));
            services.AddScoped<IStartupActivator>(_ =>
            {
                activatorConstructed = true;
                return new DelegatingActivator("Expensive", _ => Task.CompletedTask);
            });
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        activatorConstructed.Should().BeFalse("constructing an activator runs caller-supplied code too");
    }

    [Fact]
    public async Task StartAsync_reports_a_check_constructor_that_throws_as_a_failure_naming_only_its_type()
    {
        const string secretLadenMessage = "connection string contains password=hunter2";
        var thrown = new InvalidOperationException(secretLadenMessage);
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
            services.AddScoped<IStartupActivator>(_ => throw thrown));
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        var failure = ex.AggregatedFailures.Should().ContainSingle().Subject;
        failure.Code.Should().Be("startup.verifier_failed");
        failure.Message.Should().Contain("activators").And.Contain(typeof(InvalidOperationException).FullName!);
        failure.Message.Should().NotContain(secretLadenMessage);
        ex.InnerException.Should().BeSameAs(thrown);
    }

    [Fact]
    public async Task StartAsync_keeps_the_codes_of_a_configuration_exception_thrown_by_a_check_constructor()
    {
        var rootCause = new UnauthorizedAccessException("denied");
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
            services.AddScoped<IStartupActivator>(_ => throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("keyvault.read_failed", "See the inner exception."), rootCause)));
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("keyvault.read_failed");
        ex.InnerException.Should().BeSameAs(rootCause);
    }

    private sealed class ProbeOptions;

    [Fact]
    public async Task StartAsync_validates_options_before_constructing_any_verifier()
    {
        var verifierConstructed = false;
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddZeeKayDaOptions<ProbeOptions>();
            services.AddSingleton<IValidateOptions<ProbeOptions>>(
                new ValidateOptions<ProbeOptions>(Options.DefaultName, _ => false, "invalid"));
            services.AddScoped<IStartupVerifier>(_ =>
            {
                verifierConstructed = true;
                return new DelegatingVerifier("V", _ => Task.CompletedTask);
            });
        });
        var sut = new StartupVerificationHostedService(provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("configuration.options_invalid");
        verifierConstructed.Should().BeFalse("no check can be trusted against options that do not validate");
    }
}
