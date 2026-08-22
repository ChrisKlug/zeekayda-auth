using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningStartupSelfTestVerifier"/> in isolation: delegation to a registered
/// <see cref="ISigningStartupSelfTest"/>, the silent no-op when nothing is registered at all, and
/// the <see cref="LogLevel.Warning"/> warning recorded when something is registered that does not
/// implement the self-test interface — none of which are allowed to silently disable the
/// self-test without a trace (issue #437 security review, finding F2).
/// </summary>
public sealed class SigningStartupSelfTestVerifierTests
{
    private sealed class FakeSelfTestSigningService : IJwtSigningService, ISigningStartupSelfTest
    {
        public int VerifyActiveSignerAsyncCallCount { get; private set; }

        public Exception? ThrowOnVerify { get; set; }

        public ValueTask VerifyActiveSignerAsync(CancellationToken cancellationToken = default)
        {
            VerifyActiveSignerAsyncCallCount++;
            if (ThrowOnVerify is not null)
                throw ThrowOnVerify;

            return ValueTask.CompletedTask;
        }

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    /// <summary>
    /// Models an external, out-of-tree <see cref="IJwtSigningService"/> implementation written
    /// before <see cref="ISigningStartupSelfTest"/> existed — it implements only the required
    /// interface, never the optional self-test one.
    /// </summary>
    private sealed class PlainSigningService : IJwtSigningService
    {
        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private static ServiceProvider BuildProvider(IJwtSigningService? signingService)
    {
        var services = new ServiceCollection();
        if (signingService is not null)
            services.AddSingleton(signingService);

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task VerifyAsync_delegates_to_the_registered_ISigningStartupSelfTest()
    {
        var signingService = new FakeSelfTestSigningService();
        using var provider = BuildProvider(signingService);
        var sut = new SigningStartupSelfTestVerifier();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        signingService.VerifyActiveSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task VerifyAsync_propagates_a_failure_from_the_self_test_unmodified()
    {
        var signingService = new FakeSelfTestSigningService
        {
            ThrowOnVerify = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("signing.self_test_failed", "Simulated failure.")),
        };
        using var provider = BuildProvider(signingService);
        var sut = new SigningStartupSelfTestVerifier();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*self_test_failed*");
    }

    [Fact]
    public async Task VerifyAsync_is_a_no_op_when_no_IJwtSigningService_is_registered()
    {
        using var provider = BuildProvider(signingService: null);
        var sut = new SigningStartupSelfTestVerifier();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        context.Warnings.Should().BeEmpty(
            "a host that has not configured any signing provider at all is the expected shape, not a control gap worth warning about");
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_records_a_warning_naming_the_resolved_type_when_the_registered_IJwtSigningService_does_not_implement_the_self_test_interface()
    {
        using var provider = BuildProvider(new PlainSigningService());
        var sut = new SigningStartupSelfTestVerifier();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync(
            "an external IJwtSigningService written before ISigningStartupSelfTest existed must not be forced to implement it");
        context.Warnings.Should().ContainSingle(w =>
            w.Code == "signing.self_test_skipped" &&
            w.Level == LogLevel.Warning &&
            w.Args.Contains(typeof(PlainSigningService)),
            "a registered IJwtSigningService that silently drops ISigningStartupSelfTest (e.g. a decorator " +
            "registered over a real provider) must never disable the self-test without a trace " +
            "naming the concrete type that was resolved");
    }

    [Fact]
    public void Name_is_SigningStartupSelfTest()
    {
        var sut = new SigningStartupSelfTestVerifier();

        sut.Name.Should().Be("SigningStartupSelfTest");
    }
}
