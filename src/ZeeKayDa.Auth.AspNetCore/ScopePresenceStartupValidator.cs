using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies that <see cref="IScopeRepository"/> exposes the <c>openid</c> scope at application startup.
/// </summary>
/// <remarks>
/// This check is an <see cref="IHostedService"/> rather than
/// <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/> because the latter is
/// synchronous, and blocking it on an async repository call risks deadlocks. The repository is
/// resolved from a short-lived scope, consistent with <see cref="ClientRepositoryStartupActivator"/>.
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
