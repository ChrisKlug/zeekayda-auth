using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Tests;

/// <summary>An <see cref="IClaimsProvider"/> that knows every subject and has nothing to say about any of them.</summary>
internal sealed class NoClaimsProvider : IClaimsProvider
{
    public Task<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult<ClaimsResolutionResult>(new ClaimsResolutionResult.Resolved { Claims = [] });
}
