using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ClientRepositoryStartupActivatorTests
{
    [Fact]
    public async Task StartAsync_logs_warning_when_AddInMemoryClients_was_called_but_custom_repository_shadows_it()
    {
        var logger = new CapturingLogger<ClientRepositoryStartupActivator>();

        var services = new ServiceCollection();
        // Simulate that AddInMemoryClients was called — this registers InMemoryClientRegistrationOptions.
        services.AddSingleton(new InMemoryClientRegistrationOptions());
        // Register a custom IClientRepository that is NOT InMemoryClientRepository.
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        using var provider = services.BuildServiceProvider();
        var scopeFactory = provider.GetRequiredService<IServiceScopeFactory>();

        var sut = new ClientRepositoryStartupActivator(scopeFactory, logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Warning);

        logger.Entries.Single().Message.Should()
            .Contain(typeof(CustomClientRepository).FullName);
    }

    [Fact]
    public async Task StartAsync_does_not_log_warning_when_InMemoryClientRepository_is_the_resolved_repository()
    {
        // When AddInMemoryClients was NOT called, InMemoryClientRegistrationOptions is not
        // registered and GetService<InMemoryClientRegistrationOptions>() returns null.
        // The warning branch is therefore never entered, regardless of the IClientRepository type.
        var services = new ServiceCollection();
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        using var provider = services.BuildServiceProvider();
        var scopeFactory = provider.GetRequiredService<IServiceScopeFactory>();

        var sut = new ClientRepositoryStartupActivator(
            scopeFactory,
            NullSanitizingLogger<ClientRepositoryStartupActivator>.Instance);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    /// <summary>
    /// Minimal <see cref="ISanitizingLogger{T}"/> that captures log entries for assertion.
    /// </summary>
    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }

    private sealed class CustomClientRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IClientRegistration?>(null);
    }
}
