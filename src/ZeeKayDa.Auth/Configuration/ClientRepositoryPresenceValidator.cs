using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Validates at startup that an <see cref="IClientRepository"/> has been registered in the
/// dependency injection container.
/// </summary>
/// <remarks>
/// Implemented as an <see cref="IValidateOptions{TOptions}"/> for
/// <see cref="AuthorizationServerOptions"/> so that it runs as part of the existing
/// <c>ValidateOnStart()</c> hook rather than requiring a dedicated options type. A missing
/// repository fails loudly at startup instead of silently at the first request.
/// </remarks>
internal sealed class ClientRepositoryPresenceValidator : IValidateOptions<AuthorizationServerOptions>
{
    private readonly IServiceProviderIsService? _isService;

    public ClientRepositoryPresenceValidator(IServiceProviderIsService? isService)
        => _isService = isService;

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, AuthorizationServerOptions options)
    {
        // IServiceProviderIsService may be absent when a third-party DI container replaces the
        // default provider. Treat absence as "cannot determine" and skip the check rather than
        // failing with a confusing resolution error.
        if (_isService is null)
            return ValidateOptionsResult.Success;

        if (!_isService.IsService(typeof(IClientRepository)))
            return ValidateOptionsResult.Fail(
                "No IClientRepository has been registered. " +
                "Call builder.AddInMemoryClients(...) or register a custom IClientRepository implementation.");

        return ValidateOptionsResult.Success;
    }
}
