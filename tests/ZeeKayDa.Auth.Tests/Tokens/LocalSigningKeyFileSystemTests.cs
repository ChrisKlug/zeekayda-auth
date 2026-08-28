using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="LocalSigningKeyFileSystem"/> against a real file system, because its entire
/// job <em>is</em> real file-system interaction: the <c>0700</c>/<c>0600</c> mode checks, the
/// symlink walk, and the directory-ownership comparison against <c>st_uid</c> are the
/// security-critical part of the development signing key provider.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DevelopmentSigningKeySourceTests"/> covers the same failure codes through fakes, but
/// those tests only prove that <c>DevelopmentSigningKeySource</c> propagates an exception a fake
/// threw — they say nothing about whether the real checks fire. These do.
/// </para>
/// <para>
/// Platform-specific assertions are gated with <c>Assert.SkipWhen</c>/<c>Assert.SkipUnless</c> so
/// each CI runner proves its own half: POSIX modes and <c>lstat</c>-based ownership on Linux/macOS,
/// the non-inherited ACL on Windows.
/// </para>
/// <para>
/// <strong>Not covered, and why:</strong> the rejection branch of
/// <c>ValidateDirectoryChainOwnershipUnix</c> — a path component owned by a <em>different</em>
/// non-root user — cannot be staged without root to chown with, so no test here creates that
/// condition. The positive direction (a wholly current-user-owned chain is accepted, and the walk
/// stops at the first root-owned ancestor) is covered by
/// <see cref="EnsureDirectorySafe_accepts_a_directory_whose_every_component_is_owned_by_the_current_user"/>.
/// </para>
/// </remarks>
public sealed class LocalSigningKeyFileSystemTests : IDisposable
{
    private const string KeyFileName = "dev-signing-key.pem";

    private const string SamplePem =
        "-----BEGIN PRIVATE KEY-----\nc2lnbmluZy1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----\n";

    private const string RequiresUnixReason =
        "POSIX file-mode bits and lstat-based ownership are the Unix permission model.";

    private const string RequiresWindowsReason =
        "non-inherited ACL enforcement is the Windows permission model.";

    private readonly LocalSigningKeyFileSystem _sut = new();

    /// <summary>
    /// A fresh OS temp subdirectory per test, deliberately <strong>not</strong> resolved to its real
    /// path: on macOS <c>Path.GetTempPath()</c> sits under <c>/var/folders/...</c> and <c>/var</c> is
    /// a root-owned symlink to <c>/private/var</c>, so leaving it unresolved is what makes
    /// <see cref="ReadKeyFileAsync_accepts_a_key_file_under_the_OS_temp_directory_on_Unix"/> a real
    /// test of the root-owned trust anchor rather than a tautology.
    /// </summary>
    private readonly string _tempDirectory = Directory.CreateTempSubdirectory("zkda-local-fs-tests-").FullName;

    // ── EnsureDirectorySafe ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void EnsureDirectorySafe_creates_a_missing_directory_restricted_to_the_owner_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var directory = Path.Join(_tempDirectory, "signing-keys");

        _sut.EnsureDirectorySafe(directory);

        Directory.Exists(directory).Should().BeTrue();
        GetUnixMode(directory).Should()
            .Be(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    [Fact]
    public void EnsureDirectorySafe_accepts_a_directory_whose_every_component_is_owned_by_the_current_user()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var directory = Path.Join(_tempDirectory, "nested", "signing-keys");
        Directory.CreateDirectory(directory);
        SetUnixMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var act = () => _sut.EnsureDirectorySafe(directory);

        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(UnixFileMode.GroupRead)]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.GroupExecute)]
    [InlineData(UnixFileMode.OtherRead)]
    [InlineData(UnixFileMode.OtherWrite)]
    [InlineData(UnixFileMode.OtherExecute)]
    public void EnsureDirectorySafe_rejects_an_existing_directory_that_grants_any_group_or_other_access(UnixFileMode extraBit)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var directory = Path.Join(_tempDirectory, "signing-keys");
        Directory.CreateDirectory(directory);
        SetUnixMode(
            directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | extraBit);

        var act = () => _sut.EnsureDirectorySafe(directory);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*directory_too_permissive*");
    }

    [Fact]
    public void EnsureDirectorySafe_applies_a_non_inherited_owner_only_acl_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var directory = Path.Join(_tempDirectory, "signing-keys");

        _sut.EnsureDirectorySafe(directory);

        AssertOwnerOnlyProtectedAcl(directory);
    }

    // ── WriteKeyFileAsync ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task WriteKeyFileAsync_creates_the_key_file_readable_only_by_the_owner_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        GetUnixMode(keyPath).Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public async Task WriteKeyFileAsync_applies_a_non_inherited_owner_only_acl_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        AssertOwnerOnlyProtectedAcl(keyPath);
    }

    // ── ReadKeyFileAsync ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadKeyFileAsync_returns_the_bytes_WriteKeyFileAsync_wrote()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        using var content = await _sut.ReadKeyFileAsync(keyPath, TestContext.Current.CancellationToken);

        Encoding.UTF8.GetString(content.Bytes).Should().Be(SamplePem);
    }

    [Theory]
    [InlineData(UnixFileMode.GroupRead)]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherRead)]
    [InlineData(UnixFileMode.OtherWrite)]
    [InlineData(UnixFileMode.OtherExecute)]
    public async Task ReadKeyFileAsync_rejects_a_key_file_that_grants_any_group_or_other_access(UnixFileMode extraBit)
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);
        SetUnixMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | extraBit);

        var act = () => _sut.ReadKeyFileAsync(keyPath, TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*file_too_permissive*");
    }

    [Fact]
    public async Task ReadKeyFileAsync_rejects_a_key_path_that_is_itself_a_symlink()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        var realPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(realPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var linkPath = Path.Join(_tempDirectory, "link-to-key.pem");
        File.CreateSymbolicLink(linkPath, realPath);

        var act = () => _sut.ReadKeyFileAsync(linkPath, TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*symlink_detected*");
    }

    [Fact]
    public async Task ReadKeyFileAsync_rejects_a_key_file_reached_through_a_non_root_owned_symlinked_ancestor()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // The attack this check exists for: the key file itself is untampered, but a directory the
        // attacker can write to has been pointed somewhere else.
        var realDirectory = Path.Join(_tempDirectory, "real-keys");
        Directory.CreateDirectory(realDirectory);
        await _sut.WriteKeyFileAsync(
            Path.Join(realDirectory, KeyFileName), SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var linkedDirectory = Path.Join(_tempDirectory, "linked-keys");
        Directory.CreateSymbolicLink(linkedDirectory, realDirectory);

        var act = () => _sut
            .ReadKeyFileAsync(Path.Join(linkedDirectory, KeyFileName), TestContext.Current.CancellationToken)
            .AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*symlink_detected*");
    }

    [Fact]
    public async Task ReadKeyFileAsync_accepts_a_key_file_under_the_OS_temp_directory_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // The counterpart to the test above, and the reason the ancestor walk stops at the first
        // root-owned entry rather than rejecting every symlinked ancestor: on macOS the OS temp
        // directory lives under /var, which the OS itself ships as a root-owned symlink to
        // /private/var. A blanket rule would reject every key under it — including the default
        // {ContentRootPath}/.zeekayda/signing-keys for anyone whose project sits under a symlinked
        // path — for a symlink no unprivileged attacker could have planted.
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var act = () => _sut.ReadKeyFileAsync(keyPath, TestContext.Current.CancellationToken).AsTask();

        await act.Should().NotThrowAsync();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    // The three helpers below carry their own OperatingSystem.IsWindows() guard rather than relying
    // on the Assert.Skip* call at the top of each test: CA1416 cannot see that a skip aborts the
    // test, so a bare File.GetUnixFileMode/GetAccessControl call would fail the build. The
    // unreachable non-matching branch is inert — every caller is already skipped off-platform.

    private static UnixFileMode GetUnixMode(string path) =>
        OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(path);

    private static void SetUnixMode(string path, UnixFileMode mode)
    {
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, mode);
    }

    /// <summary>
    /// Asserts that <paramref name="path"/> carries a protected (non-inherited) ACL granting access
    /// to the current user and to nobody else — the Windows equivalent of <c>0700</c>/<c>0600</c>.
    /// </summary>
    private static void AssertOwnerOnlyProtectedAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var security = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl()
            : (FileSystemSecurity)new FileInfo(path).GetAccessControl();

        security.AreAccessRulesProtected.Should().BeTrue("the ACL must not inherit the parent's rules");

        var currentUser = WindowsIdentity.GetCurrent().User!;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

        // Collected with an explicit loop rather than a LINQ projection: CA1416 cannot see the
        // OperatingSystem.IsWindows() guard above through a lambda, so reading the Windows-only
        // AuthorizationRule.IdentityReference inside one fails the build on every platform.
        var identities = new List<IdentityReference>();
        foreach (FileSystemAccessRule rule in rules)
            identities.Add(rule.IdentityReference);

        identities.Should().NotBeEmpty()
            .And.AllSatisfy(identity => identity.Should().Be(currentUser));
    }

    public void Dispose()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                // A test may have narrowed or widened a file's mode in a way that blocks deletion;
                // restore owner write access across the tree before removing it.
                foreach (var file in Directory.EnumerateFiles(_tempDirectory, "*", SearchOption.AllDirectories))
                    File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);

                foreach (var directory in Directory.EnumerateDirectories(_tempDirectory, "*", SearchOption.AllDirectories))
                    File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            Directory.Delete(_tempDirectory, recursive: true);
        }
        catch
        {
            // Best-effort cleanup only — a leftover temp directory must never fail a test.
        }
    }
}
