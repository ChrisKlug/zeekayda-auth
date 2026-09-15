using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Users;

/// <summary>
/// Hands the framework a subject's claims whenever a grant becomes tokens. It returns the user's
/// whole claim set; the framework keeps only what the granted scopes and the client allow.
/// </summary>
public sealed class UserClaimsProvider(UserStore users) : IClaimsProvider
{
    public ValueTask<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context,
        CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<ClaimsResolutionResult>(users.FindBySubject(context.Sub) is { } user
            ? new ClaimsResolutionResult.Resolved { Claims = user.Claims }
            : new ClaimsResolutionResult.SubjectInvalid());
}
