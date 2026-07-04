using Azure.Core;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A minimal <see cref="TokenCredential"/> that never performs a real authentication round trip —
/// sufficient wherever a non-null credential is required by argument validation or options
/// validation but the real Key Vault reader/signer have been substituted with fakes so the
/// credential is never actually used to acquire a token.
/// </summary>
internal sealed class FakeTokenCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new("fake-token", DateTimeOffset.UtcNow.AddHours(1));

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        new(GetToken(requestContext, cancellationToken));
}
