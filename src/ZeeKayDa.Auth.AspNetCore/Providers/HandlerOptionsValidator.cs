using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Asserts, on the final values after every post-configurer, what
/// <see cref="HandlerOptionsPin{TOptions}"/> pinned, naming the provider and the member.
/// </summary>
internal sealed class HandlerOptionsValidator<TOptions>(
    ProviderRegistry registry,
    IOptions<AuthorizationServerOptions> options,
    PinnedOptionDriftRecorder recorder) : IValidateOptions<TOptions>
    where TOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Starts every failure, for a human reader. Not a provenance check: any validator could write
    /// it, so the framework's findings come from <see cref="PinnedOptionDriftRecorder"/>.
    /// </summary>
    public const string FailurePrefix = "Pinned by ZeeKayDa.Auth: ";

    private readonly IOptions<AuthorizationServerOptions> _options = options;

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !registry.Contains(name))
            return ValidateOptionsResult.Skip;

        var drifts = Forwards(options)
            .Where(forward => forward.Value is not null)
            .Select(forward => Cleared(forward.Member))
            .ToList();

        if (options is RemoteAuthenticationOptions remote)
            drifts.AddRange(RemoteDrifts(name, remote));

        // On a passing run too, so a fixed drift is never read back.
        recorder.Record(name, typeof(TOptions), drifts);

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

        // An events type replaces the pinned events wholesale; a host access-denied event pre-empts the framework's.
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

    private static string Describe(string name, PinnedOptionDrift drift) =>
        $"{FailurePrefix}the options for provider '{name}' were changed after the framework pinned " +
        $"them: {drift.Describe()} The framework owns this member; remove the configuration that " +
        "sets it.";
}
