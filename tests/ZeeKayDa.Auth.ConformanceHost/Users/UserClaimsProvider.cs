using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.ConformanceHost.Users;

/// <summary>
/// Hands the framework a subject's claims whenever a grant becomes tokens. It returns the user's
/// whole claim set; the framework keeps only what the granted scopes and the client allow.
/// </summary>
internal sealed class UserClaimsProvider(UserStore users) : IClaimsProvider
{
    public Task<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<ClaimsResolutionResult>(users.FindBySubject(context.Sub) is { } user
            ? new ClaimsResolutionResult.Resolved { Claims = user.Claims }
            : new ClaimsResolutionResult.SubjectInvalid());
}
