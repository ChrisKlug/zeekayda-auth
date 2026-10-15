using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>The rule for a development-only resource: expected in Development, refused elsewhere unless opted out.</summary>
internal static class EnvironmentGate
{
    /// <summary>What the rule says about one development-only resource on this host.</summary>
    internal enum Verdict
    {
        /// <summary><c>Development</c>: recorded at <see cref="LogLevel.Information"/>.</summary>
        ExpectedInDevelopment,

        /// <summary>Outside <c>Development</c> with the opt-out: starts, with a <see cref="LogLevel.Critical"/> reminder.</summary>
        AllowedByOptOut,

        /// <summary>Outside <c>Development</c> with no opt-out: startup fails.</summary>
        Rejected,
    }

    /// <summary>
    /// Applies the rule to an opt-out captured by the registration call, never a bindable option, so
    /// no single switch turns off every gate.
    /// </summary>
    public static Verdict Evaluate(IHostEnvironment environment, bool allowOutsideDevelopment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        if (environment.IsDevelopment())
            return Verdict.ExpectedInDevelopment;

        return allowOutsideDevelopment ? Verdict.AllowedByOptOut : Verdict.Rejected;
    }
}
