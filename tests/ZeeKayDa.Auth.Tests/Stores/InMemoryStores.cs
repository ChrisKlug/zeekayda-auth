using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>The in-memory backing stores as tests construct them, on the system clock unless one is given.</summary>
internal static class InMemoryStores
{
    public static InMemoryAuthorizationCodeBackingStore AuthorizationCodes(TimeProvider? timeProvider = null) =>
        new(timeProvider ?? TimeProvider.System);

    public static InMemoryRefreshTokenBackingStore RefreshTokens(
        TimeProvider? timeProvider = null,
        AuthorizationServerOptions? serverOptions = null) =>
        new(timeProvider ?? TimeProvider.System, Options.Create(serverOptions ?? new AuthorizationServerOptions()));
}
