namespace ZeeKayDa.Auth;

/// <summary>
/// A cheap startup check run by <c>StartupVerificationHostedService</c> after every internal startup
/// gate has passed, and before any <see cref="IStartupActivator"/>. Implement this to add a
/// framework- or provider-owned check that reads configuration or inspects the container and needs
/// async I/O or a DI scope — anything
/// <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/> structurally cannot host
/// because its <c>Validate</c> method is synchronous.
///
/// <para>
/// A check that calls into a caller-supplied extension point, performs I/O, or forces expensive
/// construction belongs in <see cref="IStartupActivator"/> instead — its phase does not run at all
/// when a verifier has already failed, so a broken configuration is reported before the work is
/// done.
/// </para>
/// </summary>
/// <remarks>
/// Report failures and warnings by calling <see cref="StartupVerificationContext.AddFailure"/> and
/// <see cref="StartupVerificationContext.AddWarning(string, string, Microsoft.Extensions.Logging.LogLevel, object?[])"/>
/// on the context passed to <see cref="IStartupCheck.VerifyAsync"/> — never throw except for a genuinely
/// unexpected failure (a DI resolution error, a third-party bug), which the runner wraps or
/// absorbs and still aborts startup on. Never log directly: the runner logs every warning on your
/// behalf, under a log category matching your own implementation type, after the internal gate
/// phase has completed. Resolve only genuine singletons from the constructor; resolve anything
/// scoped from the <see cref="IServiceProvider"/> passed to <see cref="IStartupCheck.VerifyAsync"/> — the runner
/// creates a fresh <c>AsyncServiceScope</c> for every invocation.
/// </remarks>
public interface IStartupVerifier : IStartupCheck;
