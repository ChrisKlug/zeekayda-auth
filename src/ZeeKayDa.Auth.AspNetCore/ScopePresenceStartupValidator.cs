using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies that <see cref="IScopeRepository"/> exposes the <c>openid</c> scope at application startup.
/// </summary>
/// <remarks>
/// <para>
/// The <c>openid</c> scope is mandatory for every OpenID Connect authorization request. Its absence
/// is a configuration error that should be surfaced at startup rather than silently at the first request.
/// </para>
/// <para>
/// This check is intentionally in an <see cref="IHostedService"/> rather than
/// <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/> because
/// <c>IValidateOptions&lt;T&gt;</c> is a synchronous interface and blocking on an async
/// repository call risks deadlocks in certain hosting configurations. <c>StartAsync</c> is
/// awaitable and the correct place for startup I/O.
/// </para>
/// <para>
/// The repository is resolved from a short-lived scope, consistent with
/// <see cref="ClientRepositoryStartupActivator"/>, to support scoped repository implementations.
/// </para>
/// </remarks>
internal sealed class ScopePresenceStartupValidator : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;

    public ScopePresenceStartupValidator(IServiceScopeFactory scopeFactory)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<IScopeRepository>();
        var scopes = await repository.GetScopesAsync(cancellationToken);

        if (!scopes.Any(s => string.Equals(s.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal)))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "scopes.openid_missing",
                    $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
                    $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'."));
        }
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
