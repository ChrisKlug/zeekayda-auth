using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// The one implementation of the framework's rule for a resource that is only safe in development:
/// expected in <c>Development</c>, refused outside it, and permitted outside it only when the
/// registration deliberately opted out.
/// </summary>
/// <remarks>
/// <para>
/// Every startup check that gates a development-only resource asks this type rather than testing
/// the environment itself. The rule is one decision applied to several resources, and the previous
/// arrangement — each check implementing it again — is exactly how
/// <see cref="DistributedCacheStoreStartupValidator"/> came to omit it altogether while its
/// interaction-store counterpart enforced it. A fourth check gets the policy by asking, not by
/// being copied correctly.
/// </para>
/// <para>
/// What stays with each caller is everything specific to its resource: the failure text naming what
/// is wrong and how to fix it, the warning codes, and the dependencies it resolves. Only the
/// three-way decision lives here, so this type has nothing to say about stores or caches.
/// </para>
/// </remarks>
internal static class EnvironmentGate
{
    /// <summary>What the rule says about one development-only resource on this host.</summary>
    internal enum Verdict
    {
        /// <summary>
        /// <c>Development</c>: the resource is the expected choice, and is recorded at
        /// <see cref="LogLevel.Information"/> rather than warned about.
        /// </summary>
        ExpectedInDevelopment,

        /// <summary>
        /// Outside <c>Development</c>, with the registration's opt-out set. The host starts, and is
        /// reminded at <see cref="LogLevel.Critical"/> on every start.
        /// </summary>
        AllowedByOptOut,

        /// <summary>Outside <c>Development</c> with no opt-out: startup fails.</summary>
        Rejected,
    }

    /// <summary>
    /// Applies the rule. <paramref name="allowOutsideDevelopment"/> is the value the registration
    /// call captured, never a bindable option — an opt-out is meaningless without the call it
    /// qualifies, and one host-wide switch would turn off every gate at once.
    /// </summary>
    public static Verdict Evaluate(IHostEnvironment environment, bool allowOutsideDevelopment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        if (environment.IsDevelopment())
            return Verdict.ExpectedInDevelopment;

        return allowOutsideDevelopment ? Verdict.AllowedByOptOut : Verdict.Rejected;
    }
}
