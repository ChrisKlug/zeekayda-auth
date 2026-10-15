namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct tests for <see cref="ProcessIdentityHelper"/>, the best-effort process-identity resolver
/// behind the access-denied messages. The Windows provider compiles the same source file.
/// </summary>
public sealed class ProcessIdentityHelperTests
{
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
