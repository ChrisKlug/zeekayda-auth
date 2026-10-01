using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// One options instance registered through <c>AddZeeKayDaOptions</c> or <c>ValidateWithZeeKayDa</c>,
/// validated with every other such instance so that the operator sees all of their failures at once.
/// </summary>
internal interface IValidatedOptions
{
    /// <summary>Runs every validator registered for the options, recording what each reports.</summary>
    void Validate(IServiceProvider services, OptionsFailures failures);
}
