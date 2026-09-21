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
    /// <summary>
    /// Marks this validator's failures for a human reading
    /// <see cref="OptionsValidationException.Failures"/> directly. <strong>It is not a provenance
    /// check and nothing may treat it as one</strong> — any validator can return a string that
    /// starts with these characters. The framework recovers its own findings from
    /// <see cref="PinnedOptionDriftRecorder"/>, which only it can write to.
    /// </summary>
    public const string FailurePrefix = "Pinned by ZeeKayDa.Auth: ";

    private readonly ProviderRegistry _registry;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly PinnedOptionDriftRecorder _recorder;

    public HandlerOptionsValidator(
        ProviderRegistry registry,
        IOptions<AuthorizationServerOptions> options,
        PinnedOptionDriftRecorder recorder)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(recorder);

        _registry = registry;
        _options = options;
        _recorder = recorder;
    }

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !_registry.Contains(name))
            return ValidateOptionsResult.Skip;

        var drifts = Forwards(options)
            .Where(forward => forward.Value is not null)
            .Select(forward => Cleared(forward.Member))
            .ToList();

        if (options is RemoteAuthenticationOptions remote)
            drifts.AddRange(RemoteDrifts(name, remote));

        // Recorded on every validating run, including the passing one: an empty record overwrites
        // a previous failure's findings, so the activator can never read a drift that has since
        // been fixed.
        _recorder.Record(name, typeof(TOptions), drifts);

        return drifts.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(drifts.Select(drift => Describe(name, drift)).ToList());
    }

    private IEnumerable<PinnedOptionDrift> RemoteDrifts(string name, RemoteAuthenticationOptions remote)
    {
        var callbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);

        if (remote.CallbackPath != callbackPath)
            yield return Drifted(nameof(remote.CallbackPath), callbackPath.Value!);

        if (!string.Equals(remote.SignInScheme, ZeeKayDaCookies.External, StringComparison.Ordinal))
            yield return Drifted(nameof(remote.SignInScheme), ZeeKayDaCookies.External);

        if (remote.AccessDeniedPath.HasValue)
            yield return Cleared(nameof(remote.AccessDeniedPath));

        // Either would put the refusal outcome outside the framework's control: events resolved
        // from the container replace the pinned event object wholesale, and a host access-denied
        // event could handle or skip the refusal before the framework records it.
        if (remote.EventsType is not null)
            yield return Cleared(nameof(remote.EventsType));

        if (remote.Events is not { } events || !ReferenceEquals(events.OnAccessDenied, ProviderAccessDenied.Handler))
            yield return Cleared("Events.OnAccessDenied");
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

    private static PinnedOptionDrift Drifted(string member, string expected) => new(member, expected);

    private static PinnedOptionDrift Cleared(string member) => new(member, Expected: null);

    // The string form handed to Microsoft.Extensions.Options, built from the same drift the
    // recorder carries, so the two descriptions can never drift apart themselves.
    private static string Describe(string name, PinnedOptionDrift drift) =>
        $"{FailurePrefix}the options for provider '{name}' were changed after the framework pinned " +
        $"them: {drift.Describe()} The framework owns this member; remove the configuration that " +
        "sets it.";
}
