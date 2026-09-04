using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Asserts what <see cref="ProviderOptionsPin{TOptions}"/> pinned. Validation runs after every
/// post-configurer, so this sees the final values and fails any registered provider's options
/// whose callback path, sign-in scheme, access-denied path or forwarding differ from the pins —
/// naming the scheme and the member.
/// </summary>
/// <remarks>
/// Without this, a <c>PostConfigure</c> for the same scheme registered later by the host or a
/// library would win silently, and the provider would sign into the wrong cookie or call back to
/// a path nothing serves. The failure surfaces at startup because
/// <see cref="ProviderOptionsStartupActivator"/> resolves each provider's options once.
/// </remarks>
internal sealed class ProviderOptionsValidator<TOptions> : IValidateOptions<TOptions>
    where TOptions : RemoteAuthenticationOptions
{
    private readonly ProviderRegistry _registry;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public ProviderOptionsValidator(ProviderRegistry registry, IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);

        _registry = registry;
        _options = options;
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !_registry.Contains(name))
            return ValidateOptionsResult.Skip;

        var failures = new List<string>();
        var callbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);

        if (options.CallbackPath != callbackPath)
            failures.Add(Drifted(name, nameof(options.CallbackPath), callbackPath.Value!));

        if (!string.Equals(options.SignInScheme, ZeeKayDaCookies.External, StringComparison.Ordinal))
            failures.Add(Drifted(name, nameof(options.SignInScheme), ZeeKayDaCookies.External));

        if (options.AccessDeniedPath.HasValue)
            failures.Add(Cleared(name, nameof(options.AccessDeniedPath)));

        foreach (var (member, value) in Forwards(options).Where(forward => forward.Value is not null))
            failures.Add(Cleared(name, member));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static IEnumerable<(string Member, object? Value)> Forwards(TOptions options) =>
    [
        (nameof(options.ForwardDefault), options.ForwardDefault),
        (nameof(options.ForwardDefaultSelector), options.ForwardDefaultSelector),
        (nameof(options.ForwardAuthenticate), options.ForwardAuthenticate),
        (nameof(options.ForwardChallenge), options.ForwardChallenge),
        (nameof(options.ForwardForbid), options.ForwardForbid),
        (nameof(options.ForwardSignIn), options.ForwardSignIn),
        (nameof(options.ForwardSignOut), options.ForwardSignOut),
    ];

    private static string Drifted(string name, string member, string expected) =>
        $"The options for provider '{name}' were changed after ZeeKayDa.Auth pinned them: {member} " +
        $"must be '{expected}'. The framework owns this member; remove the configuration that sets it.";

    private static string Cleared(string name, string member) =>
        $"The options for provider '{name}' were changed after ZeeKayDa.Auth pinned them: {member} " +
        "must not be set. The framework owns this member; remove the configuration that sets it.";
}
