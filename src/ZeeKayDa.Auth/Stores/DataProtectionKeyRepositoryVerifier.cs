using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Warns outside Development when the host configured no Data Protection key repository, since the
/// stores' protected entries then live in a key ring the runtime's default may lose or not share. A
/// host that registered its own key manager type owns its storage, and is not warned.
/// </summary>
internal sealed class DataProtectionKeyRepositoryVerifier(
    IOptions<KeyManagementOptions> keyManagementOptions,
    IHostEnvironment environment,
    ServiceLifetimeScanner registrations) : IStartupVerifier
{
    internal const string NotConfiguredCode = "data_protection.key_repository_not_configured";

    /// <summary>The variable Data Protection itself reads to detect Azure App Service.</summary>
    internal const string AppServiceInstanceVariable = "WEBSITE_INSTANCE_ID";

    internal const string NotConfiguredMessage =
        "No Data Protection key repository is configured, so the runtime's default key storage applies. " +
        "ZeeKayDa.Auth protects stored authorization codes, interaction entries and refresh tokens with " +
        "Data Protection; a default key ring on a container's own file system does not survive a redeploy " +
        "and is not shared with other instances, and every entry it protected becomes unreadable. " +
        "Configure a persisted key repository shared by every instance.";

    internal const string AppServiceMessage =
        "No Data Protection key repository is configured, so the Azure App Service default key storage applies. " +
        "That key ring is shared only by the instances of one deployment slot: a slot swap loses it, and so " +
        "does a Linux custom container without WEBSITES_ENABLE_APP_SERVICE_STORAGE=true, making every stored " +
        "authorization code, interaction entry and refresh token unreadable. Configure an explicit key " +
        "repository shared by every slot and instance.";

    /// <inheritdoc/>
    public string Name => "DataProtectionKeyRepository";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        Verify(context, Environment.GetEnvironmentVariable(AppServiceInstanceVariable));
        return Task.CompletedTask;
    }

    /// <summary>The check, with the App Service variable passed in so a test need not set it on the process.</summary>
    internal void Verify(StartupVerificationContext context, string? appServiceInstanceId)
    {
        if (environment.IsDevelopment() || keyManagementOptions.Value.XmlRepository is not null || KeyManagerReplaced())
            return;

        if (string.IsNullOrEmpty(appServiceInstanceId))
            context.AddWarning(NotConfiguredCode, NotConfiguredMessage);
        else
            context.AddWarning(NotConfiguredCode, AppServiceMessage);
    }

    /// <summary>
    /// Only Data Protection's own key manager falls back to the default storage. A factory
    /// registration may be wrapping it, so only a named type or instance counts as a replacement.
    /// </summary>
    private bool KeyManagerReplaced() =>
        registrations.RegistrationsOf(typeof(IKeyManager)).LastOrDefault() is { } last
        && (last.ImplementationType ?? last.ImplementationInstance?.GetType()) is { } type
        && type != typeof(XmlKeyManager);
}
