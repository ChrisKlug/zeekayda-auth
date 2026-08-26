namespace ZeeKayDa.Auth;

/// <summary>
/// The shape every startup check shares: a name for log attribution, and one method the runner
/// invokes. Never implemented directly — implement <see cref="IStartupVerifier"/> for a check that
/// only reads configuration, or <see cref="IStartupActivator"/> for one that calls into a
/// caller-supplied extension point.
/// </summary>
/// <remarks>
/// The split exists so the runner can refuse to do expensive work when the configuration is already
/// known to be broken, without introducing an ordering knob. Which collection a check is registered
/// in decides which phase it runs in; nothing a check returns can influence order, and there is no
/// priority or ordering attribute in any of these contracts.
/// </remarks>
public interface IStartupCheck
{
    /// <summary>
    /// A stable name used for log attribution and diagnostics only. This is <b>not</b> an ordering
    /// or priority hint — execution order is DI registration order within a phase, and nothing a
    /// check returns can influence it.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Runs this check. Report outcomes on <paramref name="context"/> rather than throwing; the
    /// runner treats a thrown <see cref="ZeeKayDaConfigurationException"/> as if its
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had been added to
    /// <paramref name="context"/>, and records any other exception as an unexpected failure without
    /// discarding what earlier checks in the same phase already reported.
    /// </summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="scopedServices">
    /// The <see cref="IServiceProvider"/> for a fresh <c>AsyncServiceScope</c> created for this
    /// invocation. Resolve scoped dependencies from here, not from the constructor.
    /// </param>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down while startup verification is running.</param>
    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}
