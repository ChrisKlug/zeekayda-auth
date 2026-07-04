namespace ZeeKayDa.Auth.Tests.Logging;

/// <summary>
/// Documents the visibility invariants of the sanitizing-logger types (ADR 0011 Amendment 2(d)).
/// </summary>
public sealed class ISanitizingLoggerVisibilityTests
{
    [Fact]
    public void ISanitizingLogger_is_public()
    {
        // Public so that packages referencing only core ZeeKayDa.Auth (e.g.
        // ZeeKayDa.Auth.AzureKeyVault, and genuine third-party signing/storage providers) can
        // constructor-inject it without InternalsVisibleTo, which can only ever name first-party
        // assemblies at build time. This mirrors why JwkThumbprint is public
        // (ADR 0011 Amendment 2(c)).
        //
        // This was previously asserted false, citing a concern that the ZEEKAYDA0002 analyzer's
        // logger-implementation exemption (InterpolatedStringLogAnalyzer.IsInLoggerImplementation)
        // matches ISanitizingLogger<T> by visibility. That concern does not hold against the
        // current analyzer: the exemption is gated on `ContainingAssembly.Name == "ZeeKayDa.Auth"`
        // alone, which no type outside the core assembly can ever satisfy regardless of the
        // interface's own visibility. Confirmed empirically by building a throwaway friend-assembly
        // implementation with a non-constant log template while the interface was still internal —
        // ZEEKAYDA0002 fired anyway. See
        // InterpolatedStringLogAnalyzerTests.Diagnostic_still_fires_inside_friend_assembly_class_implementing_a_PUBLIC_ISanitizingLogger
        // for the permanent regression coverage of that guarantee.
        var type = typeof(ZeeKayDa.Auth.Logging.ISanitizingLogger<>);
        type.IsVisible.Should().BeTrue();
        type.IsPublic.Should().BeTrue();
    }

    [Fact]
    public void SecretSanitizingLogger_remains_internal()
    {
        // The interface is the only part of the contract that needs to cross package boundaries.
        // The concrete implementation — and its SensitiveKeys redaction allowlist — stays internal,
        // exactly like SigningAlgorithms stays internal while JwkThumbprint (extracted from it)
        // went public.
        var type = typeof(ZeeKayDa.Auth.Logging.SecretSanitizingLogger<>);
        type.IsVisible.Should().BeFalse();
        type.IsPublic.Should().BeFalse();
    }
}
