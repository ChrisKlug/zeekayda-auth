namespace ZeeKayDa.Auth;

/// <summary>
/// Validates every options type registered through <c>AddZeeKayDaOptions</c> or
/// <c>ValidateWithZeeKayDa</c> at host start, for a host that never calls <c>MapZeeKayDaAuth()</c>.
/// </summary>
/// <remarks>
/// A gate, not a verifier: nothing else can be trusted to run against options that do not validate.
/// </remarks>
internal sealed class ValidatedOptionsGate : IStartupVerificationGate
{
    public string Name => "ValidatedOptions";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ValidatedOptionsCheck.ThrowIfAnyInvalid(scopedServices);
        return ValueTask.CompletedTask;
    }
}
