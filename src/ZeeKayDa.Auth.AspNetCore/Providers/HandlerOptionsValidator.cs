using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Asserts what <see cref="HandlerOptionsPin{TOptions}"/> pinned. Validation runs after every
/// post-configurer, so this sees the final values and fails any registered provider's options
/// whose forwarding — or, on a remote one, callback path, sign-in scheme, access-denied path,
/// access-denied event or events type — differ from the pins, naming the scheme and the member.
/// </summary>
/// <remarks>
/// Without this, a <c>PostConfigure</c> for the same scheme registered later by the host or a
/// library would win silently, and the provider would sign into the wrong cookie or call back to
/// a path nothing serves. The failure surfaces at startup because
/// <see cref="HandlerOptionsStartupActivator"/> resolves each provider's options once.
/// </remarks>
internal sealed class HandlerOptionsValidator<TOptions> : IValidateOptions<TOptions>
    where TOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Every failure this validator produces starts with this, so the startup activator can tell
    /// the framework's own text — safe to surface, it names only a scheme and a member — from a
    /// provider's or host's validation text, which it never copies.
    /// </summary>
    public const string FailurePrefix = "Pinned by ZeeKayDa.Auth: ";

    private readonly ProviderRegistry _registry;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public HandlerOptionsValidator(ProviderRegistry registry, IOptions<AuthorizationServerOptions> options)
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

        var failures = Forwards(options)
            .Where(forward => forward.Value is not null)
            .Select(forward => Cleared(name, forward.Member))
            .ToList();

        if (options is RemoteAuthenticationOptions remote)
            failures.AddRange(RemoteFailures(name, remote));

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private IEnumerable<string> RemoteFailures(string name, RemoteAuthenticationOptions remote)
    {
        var callbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);

        if (remote.CallbackPath != callbackPath)
            yield return Drifted(name, nameof(remote.CallbackPath), callbackPath.Value!);

        if (!string.Equals(remote.SignInScheme, ZeeKayDaCookies.External, StringComparison.Ordinal))
            yield return Drifted(name, nameof(remote.SignInScheme), ZeeKayDaCookies.External);

        if (remote.AccessDeniedPath.HasValue)
            yield return Cleared(name, nameof(remote.AccessDeniedPath));

        // Either would put the refusal outcome outside the framework's control: events resolved
        // from the container replace the pinned event object wholesale, and a host access-denied
        // event could handle or skip the refusal before the framework records it.
        if (remote.EventsType is not null)
            yield return Cleared(name, nameof(remote.EventsType));

        if (remote.Events is not { } events || !ReferenceEquals(events.OnAccessDenied, ProviderAccessDenied.Handler))
            yield return Cleared(name, "Events.OnAccessDenied");
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
        $"{FailurePrefix}the options for provider '{name}' were changed after the framework pinned " +
        $"them: {member} must be '{expected}'. The framework owns this member; remove the " +
        "configuration that sets it.";

    private static string Cleared(string name, string member) =>
        $"{FailurePrefix}the options for provider '{name}' were changed after the framework pinned " +
        $"them: {member} must not be set. The framework owns this member; remove the configuration " +
        "that sets it.";
}
