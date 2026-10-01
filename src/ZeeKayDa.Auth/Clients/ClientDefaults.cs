using System.Collections.Frozen;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// The value of every <see cref="IClient"/> member a client leaves unset, each the safe answer. The
/// interface's default members, <see cref="Client"/>'s initialisers and <see cref="ClientOptions"/>
/// all read these, so the three cannot drift.
/// </summary>
internal static class ClientDefaults
{
    // A public client that forgets to say so has no secret, so it fails validation loudly.
    internal const bool IsPublic = false;

    internal static readonly IReadOnlySet<string> RedirectUris = FrozenSet<string>.Empty;

    internal static readonly IReadOnlySet<string> PostLogoutRedirectUris = FrozenSet<string>.Empty;

    internal static readonly IReadOnlySet<string> AllowedScopes = FrozenSet<string>.Empty;

    internal static readonly IReadOnlySet<GrantType> AllowedGrantTypes =
        new[] { GrantType.AuthorizationCode }.ToFrozenSet();

    internal static readonly IReadOnlySet<ResponseType> AllowedResponseTypes =
        new[] { ResponseType.Code }.ToFrozenSet();

    internal static readonly IReadOnlySet<ResponseMode> AllowedResponseModes =
        new[] { ResponseMode.Query }.ToFrozenSet();

    internal static readonly IReadOnlySet<PromptValue> AllowedPromptValues = FrozenSet<PromptValue>.Empty;

    internal const bool EnableZkdErrorCodes = false;

    internal const bool RequireConsent = true;

    internal const bool SkipLogoutConfirmation = false;

    internal const bool RequirePkce = true;

    internal static readonly IReadOnlySet<string> AdditionalClaims = FrozenSet<string>.Empty;

    private static readonly IReadOnlySet<string> PublicAuthMethods =
        new[] { TokenEndpointAuthMethods.None }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly IReadOnlySet<string> ConfidentialAuthMethods =
        new[] { TokenEndpointAuthMethods.ClientSecretBasic }.ToFrozenSet(StringComparer.Ordinal);

    internal static IReadOnlySet<string> AllowedTokenEndpointAuthMethods(bool isPublic) =>
        isPublic ? PublicAuthMethods : ConfidentialAuthMethods;
}
