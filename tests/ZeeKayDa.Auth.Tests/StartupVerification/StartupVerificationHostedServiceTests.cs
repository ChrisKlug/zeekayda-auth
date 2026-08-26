using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.StartupVerification;

/// <summary>
/// Exercises <see cref="StartupVerificationHostedService"/>'s two-phase <c>StartAsync</c>: gate
/// abort-on-first-failure semantics, verifier run-all-then-aggregate semantics, the unexpected
/// exception special cases, and — critically — that logging never happens before
/// the gate phase has completed and that a warning's structured arguments still reach
/// <c>SecretSanitizingLogger</c>'s by-key redaction after being composed with the runner's own
/// constant prefix.
/// </summary>
public sealed class StartupVerificationHostedServiceTests
{
    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    /// <summary>Shared sink for <see cref="CapturingLogger{T}"/>, keyed by the closed generic type
    /// the reflective <c>ISanitizingLogger&lt;&gt;</c> resolution was made against.</summary>
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

    /// <summary>Wraps a real <see cref="IServiceProvider"/> and records every resolution attempt
    /// made against a closed generic <c>ISanitizingLogger&lt;&gt;</c>.</summary>
    private sealed class ResolutionSpyServiceProvider(IServiceProvider inner) : IServiceProvider
    {
        public List<Type> SanitizingLoggerResolutions { get; } = [];

        public object? GetService(Type serviceType)
        {
            if (serviceType.IsGenericType && serviceType.GetGenericTypeDefinition() == typeof(ISanitizingLogger<>))
                SanitizingLoggerResolutions.Add(serviceType);

            return inner.GetService(serviceType);
        }
    }

    private sealed class DelegatingGate(string name, Action<StartupVerificationContext> act) : IStartupVerificationGate
    {
        public string Name => name;

        public ValueTask VerifyAsync(StartupVerificationContext context, IServiceProvider scopedServices, CancellationToken cancellationToken)
        {
            act(context);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class DelegatingVerifier(string name, Func<StartupVerificationContext, ValueTask> act) : IStartupVerifier
    {
        public string Name => name;

        public ValueTask VerifyAsync(StartupVerificationContext context, IServiceProvider scopedServices, CancellationToken cancellationToken)
            => act(context);
    }

    private sealed class DelegatingActivator(string name, Func<StartupVerificationContext, ValueTask> act) : IStartupActivator
    {
        public string Name => name;

        public ValueTask VerifyAsync(StartupVerificationContext context, IServiceProvider scopedServices, CancellationToken cancellationToken)
            => act(context);
    }

    private static ServiceProvider BuildProviderWithSanitizingLogging(
        out LogSink sink, Action<ServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        var localSink = new LogSink();
        services.AddSingleton(localSink);
        services.AddSingleton(typeof(ILogger<>), typeof(CapturingLogger<>));
        services.AddSingleton(typeof(ISanitizingLogger<>), typeof(SecretSanitizingLogger<>));
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
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(
            out var sink, services => services.AddSingleton<IStartupVerifier>(verifier));

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        var entry = sink.Entries.Should().ContainSingle().Subject;
        entry.Category.Should().Be(verifier.GetType(), "the log category must be the verifier's own runtime type, not the runner's");
        entry.Pairs.Should().Contain(kv =>
            kv.Key == "{OriginalFormat}" && (string?)kv.Value == "[{Verifier}] {ErrorCode}: value {client_secret}");
        entry.Pairs.Should().Contain(kv => kv.Key == "client_secret" && (string?)kv.Value == "[REDACTED]");
        entry.Pairs.Should().Contain(kv => kv.Key == "Verifier" && (string?)kv.Value == "RedactionProbe");

        // The runner's own placeholder is named {ErrorCode}, not {Code}, so it does not collide
        // with SecretSanitizingLogger.SensitiveKeys' "code" entry: the warning's stable
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
            return ValueTask.CompletedTask;
        });
        var goodVerifier = new DelegatingVerifier("GoodVerifier", context =>
        {
            context.AddFailure("real.failure", "a genuine configuration problem");
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(
            out _,
            services =>
            {
                services.AddSingleton<IStartupVerifier>(badVerifier);
                services.AddSingleton<IStartupVerifier>(goodVerifier);
            });

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().Contain(f => f.Code == "startup.warning_log_failed");
        exception.Which.AggregatedFailures.Should().Contain(
            f => f.Code == "real.failure",
            "a warning that fails to log must not discard an already-aggregated genuine configuration failure");
    }

    // ── Phase 1 (gates): no logging until the gate phase has completed ─────────────────────────────

    [Fact]
    public async Task StartAsync_does_not_resolve_ISanitizingLogger_while_a_later_gate_is_still_running()
    {
        using var provider = BuildProviderWithSanitizingLogging(out _);
        var spy = new ResolutionSpyServiceProvider(provider);
        var resolutionsWhenSecondGateRan = -1;

        var gateA = new DelegatingGate("A", context => context.AddWarning("gate.a", "warned"));
        var gateB = new DelegatingGate("B", _ => resolutionsWhenSecondGateRan = spy.SanitizingLoggerResolutions.Count);

        var sut = new StartupVerificationHostedService([gateA, gateB], spy, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        resolutionsWhenSecondGateRan.Should().Be(0,
            "nothing may be resolved or logged through ISanitizingLogger<> until every gate has passed");
    }

    [Fact]
    public async Task StartAsync_throws_immediately_when_a_gate_warning_fails_to_log()
    {
        // Phase 1 has no failures list to aggregate into — a gate warning that fails to log must
        // still fail closed, but by throwing directly rather than joining an aggregation phase
        // that doesn't exist here (contrast with the verifier-phase case above, which aggregates).
        using var provider = BuildProviderWithSanitizingLogging(out _);
        var gate = new DelegatingGate("BadWarningGate", context => context.AddWarning("bad.warning", "value {missing}"));

        var sut = new StartupVerificationHostedService([gate], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("startup.warning_log_failed");
    }

    // ── Phase 2 (verifiers): resolved lazily inside StartAsync, not constructor-injected ────────────

    [Fact]
    public async Task StartAsync_does_not_construct_verifiers_until_the_gate_phase_has_completed()
    {
        var order = new List<string>();
        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(_ =>
        {
            order.Add("verifier-constructed");
            return new DelegatingVerifier("V", _ => ValueTask.CompletedTask);
        });

        using var provider = services.BuildServiceProvider();
        var gate = new DelegatingGate("gate", _ => order.Add("gate-ran"));

        var sut = new StartupVerificationHostedService([gate], provider, provider.GetRequiredService<IServiceScopeFactory>());

        order.Should().BeEmpty("constructing the runner itself must not resolve IEnumerable<IStartupVerifier>");

        await sut.StartAsync(TestContext.Current.CancellationToken);

        order.Should().Equal("gate-ran", "verifier-constructed");
    }

    // ── Phase 1 aggregation semantics: abort immediately, no aggregation ────────────────────────────

    [Fact]
    public async Task StartAsync_aborts_immediately_on_the_first_gate_failure_without_running_later_gates()
    {
        var laterGateRan = false;
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();

        var failingGate = new DelegatingGate("failing", context => context.AddFailure("gate.fail", "boom"));
        var laterGate = new DelegatingGate("later", _ => laterGateRan = true);

        var sut = new StartupVerificationHostedService([failingGate, laterGate], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("gate.fail");
        laterGateRan.Should().BeFalse("a later gate must never run once an earlier one has failed");
    }

    // ── Phase 2 aggregation semantics: run all, aggregate, throw once ───────────────────────────────

    [Fact]
    public async Task StartAsync_runs_every_verifier_and_aggregates_all_failures_into_one_exception()
    {
        var verifier1Ran = false;
        var verifier2Ran = false;
        var verifier1 = new DelegatingVerifier("V1", context =>
        {
            verifier1Ran = true;
            context.AddFailure("v1.fail", "first failure");
            return ValueTask.CompletedTask;
        });
        var verifier2 = new DelegatingVerifier("V2", context =>
        {
            verifier2Ran = true;
            context.AddFailure("v2.fail", "second failure");
            return ValueTask.CompletedTask;
        });

        var services = new ServiceCollection();
        services.AddSingleton<IStartupVerifier>(verifier1);
        services.AddSingleton<IStartupVerifier>(verifier2);
        using var provider = services.BuildServiceProvider();

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("signing.self_test_failed");
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

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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

        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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
            return ValueTask.CompletedTask;
        });
        var activator = new DelegatingActivator("Expensive", _ =>
        {
            activatorRan = true;
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(verifier);
            services.AddSingleton<IStartupActivator>(activator);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("config.broken");
        activatorRan.Should().BeFalse();
    }

    [Fact]
    public async Task StartAsync_runs_activators_when_every_verifier_passed()
    {
        var activatorRan = false;
        var verifier = new DelegatingVerifier("Cheap", _ => ValueTask.CompletedTask);
        var activator = new DelegatingActivator("Expensive", _ =>
        {
            activatorRan = true;
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(verifier);
            services.AddSingleton<IStartupActivator>(activator);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        await sut.StartAsync(TestContext.Current.CancellationToken);

        activatorRan.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_aggregates_activator_failures_across_the_whole_activator_phase()
    {
        var first = new DelegatingActivator("First", context =>
        {
            context.AddFailure("first.failed", "First.");
            return ValueTask.CompletedTask;
        });
        var second = new DelegatingActivator("Second", context =>
        {
            context.AddFailure("second.failed", "Second.");
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupActivator>(first);
            services.AddSingleton<IStartupActivator>(second);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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
            return ValueTask.CompletedTask;
        });
        var throwing = new DelegatingVerifier("Throwing", _ => throw new InvalidOperationException("boom"));
        var later = new DelegatingVerifier("Later", context =>
        {
            context.AddFailure("genuine.three", "Three.");
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(failing);
            services.AddSingleton<IStartupVerifier>(throwing);
            services.AddSingleton<IStartupVerifier>(later);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(throwing);
            services.AddSingleton<IStartupVerifier>(failing);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var ex = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        ex.AggregatedFailures.Should().HaveCount(2);
        ex.InnerException.Should().BeOfType<AggregateException>()
            .Which.InnerExceptions.Should().HaveCount(2);
    }

    // ── Gate warnings survive a later gate's failure (#500) ──────────────────────────────────────

    [Fact]
    public async Task StartAsync_logs_warnings_buffered_after_the_logger_gate_passed_when_a_later_gate_fails()
    {
        var loggerGate = CreateGenuineSanitizingLoggerGate();
        var warning = new DelegatingGate("Warning", context => context.AddWarning("gate.warned", "something"));
        var failing = new DelegatingGate("Failing", context => context.AddFailure("gate.failed", "Simulated."));
        using var provider = BuildProviderWithSanitizingLogging(out var sink);
        var sut = new StartupVerificationHostedService(
            [loggerGate, warning, failing], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        sink.Entries.Should().ContainSingle("the logger was proved trustworthy before the warning was buffered");
    }

    [Fact]
    public async Task StartAsync_discards_warnings_buffered_before_the_logger_gate_fails()
    {
        // A gate registered ahead of the sanitizing-logger gate can buffer a warning before anything
        // has established that the logger redacts. If that gate then fails, flushing the buffer would
        // log through the very logger it just proved shadowed.
        var warning = new DelegatingGate("Warning", context => context.AddWarning("gate.warned", "something"));
        var shadowedLoggerGate = CreateShadowedSanitizingLoggerGate();
        using var provider = BuildProviderWithSanitizingLogging(out var sink);
        var sut = new StartupVerificationHostedService(
            [warning, shadowedLoggerGate], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        sink.Entries.Should().BeEmpty("nothing may be logged until the logger is known to redact");
    }

    private static SanitizingLoggerRegistrationGate CreateGenuineSanitizingLoggerGate()
        => new(
            new SecretSanitizingLogger<SanitizingLoggerRegistrationGate>(
                NullLogger<SanitizingLoggerRegistrationGate>.Instance,
                Options.Create(new AuthorizationServerOptions())),
            new SanitizingLoggerClosedOverrideScanner(new ServiceCollection()));

    private static SanitizingLoggerRegistrationGate CreateShadowedSanitizingLoggerGate()
        => new(
            new NullSanitizingLogger<SanitizingLoggerRegistrationGate>(),
            new SanitizingLoggerClosedOverrideScanner(new ServiceCollection()));

    // ── A check registered as the base interface never runs, so it fails the host ────────────────

    [Fact]
    public async Task StartAsync_fails_when_a_check_is_registered_as_IStartupCheck()
    {
        // AddSingleton<IStartupCheck, X>() compiles and reads as correct, but MS.DI does not resolve
        // a derived registration for a base service type, so the runner would never enumerate it.
        var check = new DelegatingVerifier("Misregistered", _ => ValueTask.CompletedTask);
        using var provider = BuildProviderWithSanitizingLogging(
            out _, services => services.AddSingleton<IStartupCheck>(check));
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        var failure = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle().Subject;
        failure.Code.Should().Be("startup.check_registered_as_base_interface");
        failure.Message.Should().Contain(typeof(DelegatingVerifier).FullName!);
    }

    [Fact]
    public async Task StartAsync_runs_normally_when_no_check_is_registered_as_IStartupCheck()
    {
        var verifier = new DelegatingVerifier("Fine", _ => ValueTask.CompletedTask);
        using var provider = BuildProviderWithSanitizingLogging(
            out _, services => services.AddSingleton<IStartupVerifier>(verifier));
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_collapses_identical_failures_reported_by_two_checks_in_one_phase()
    {
        // Two checks that both need the signing key set both report its failure, because each
        // genuinely needs it initialized. That is one broken configuration, not two problems.
        var first = new DelegatingActivator("First", context =>
        {
            context.AddFailure("signing.source_unavailable", "The source refused.");
            return ValueTask.CompletedTask;
        });
        var second = new DelegatingActivator("Second", context =>
        {
            context.AddFailure("signing.source_unavailable", "The source refused.");
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupActivator>(first);
            services.AddSingleton<IStartupActivator>(second);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

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
            return ValueTask.CompletedTask;
        });
        var second = new DelegatingVerifier("Second", context =>
        {
            context.AddFailure("client.invalid", "Client 'b' is invalid.");
            return ValueTask.CompletedTask;
        });
        using var provider = BuildProviderWithSanitizingLogging(out _, services =>
        {
            services.AddSingleton<IStartupVerifier>(first);
            services.AddSingleton<IStartupVerifier>(second);
        });
        var sut = new StartupVerificationHostedService([], provider, provider.GetRequiredService<IServiceScopeFactory>());

        var act = async () => await sut.StartAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().HaveCount(2);
    }
}
