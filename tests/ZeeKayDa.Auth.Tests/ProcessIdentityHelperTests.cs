namespace ZeeKayDa.Auth.Tests;

/// <summary>
/// Direct tests for <see cref="ProcessIdentityHelper"/>, the shared best-effort process-identity
/// resolver used by both <c>ZeeKayDa.Auth.FileSystem</c>'s and <c>ZeeKayDa.Auth.Windows</c>'s
/// access-denied diagnostic messages (issue #406; consolidated from two verbatim copies per
/// PR #410's review).
/// </summary>
public sealed class ProcessIdentityHelperTests
{
    [Fact]
    public void FormatIdentitySuffix_includes_the_identity_when_resolution_succeeds()
    {
        var suffix = ProcessIdentityHelper.FormatIdentitySuffix("svc-account");

        suffix.Should().Be(" (running as 'svc-account')");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FormatIdentitySuffix_omits_the_identity_when_resolution_degrades(string? identity)
    {
        // Best-effort degradation (issue #406): if the platform-specific identity lookup throws or
        // returns empty, the caller passes null/empty through here rather than letting a secondary
        // failure produce a misleading or malformed message.
        var suffix = ProcessIdentityHelper.FormatIdentitySuffix(identity);

        suffix.Should().BeEmpty();
    }

    [Fact]
    public void TryResolveProcessIdentity_never_throws()
    {
        // The whole contract of this best-effort resolver is "never fail the real throw it is
        // enriching" (PR #410's review): on this host it should resolve to a non-null value, but the
        // regression this guards against is any exception escaping — including platform-specific
        // failures such as IOException from Environment.UserName on Unix, or
        // IdentityNotMappedException/SystemException from WindowsIdentity.GetCurrent() on Windows.
        var act = () => ProcessIdentityHelper.TryResolveProcessIdentity();

        act.Should().NotThrow();
    }
}
