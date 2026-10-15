using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>Options registered through <c>AddZeeKayDaOptions</c>, validated together with all the others.</summary>
internal interface IValidatedOptions
{
    /// <summary>Runs every validator registered for the options, recording what each reports.</summary>
    void Validate(IServiceProvider services, OptionsFailures failures);
}
