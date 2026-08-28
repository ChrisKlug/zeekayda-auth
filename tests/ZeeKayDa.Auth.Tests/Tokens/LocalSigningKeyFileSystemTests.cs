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
/// <strong>Not covered, and why:</strong> two branches of
/// <c>ValidateDirectoryChainOwnershipUnix</c> cannot be staged unprivileged. A path component owned
/// by a <em>different</em> non-root user needs root to <c>chown</c> with — and a symlink's owner is
/// fixed at <c>symlink(2)</c>, so a foreign-owned <em>link entry</em> that is not root's needs
/// <c>CAP_CHOWN</c> too. The <c>linkOwnerUid is null</c> branch (an <c>lstat</c> failure, or an
/// architecture whose struct layout <c>PosixInterop</c> does not bind) has no unprivileged trigger
/// either. The mixed root/current-user shapes that <em>can</em> be staged are covered by
/// <see cref="EnsureDirectorySafe_rejects_an_ancestor_that_is_a_symlink_to_a_root_owned_directory"/>
/// and <see cref="EnsureDirectorySafe_accepts_a_sticky_world_writable_ancestor"/>.
/// The positive direction (a wholly current-user-owned chain is accepted, and the walk
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

    /// <summary>
    /// The literal <c>/tmp</c>, never <c>Path.GetTempPath()</c>. Root-owned by POSIX/FHS convention
    /// on every mainstream Unix (and on every GitHub Actions runner this suite runs on), and on
    /// macOS a root-owned <em>symlink</em> to <c>/private/tmp</c> — which is exactly the ancestor
    /// shape the trust anchor exists for. <c>Path.GetTempPath()</c> resolves to a user-owned
    /// directory under <c>/var/folders/...</c> on macOS and would collapse these tests into a case
    /// that passes under both the correct and the broken implementation.
    /// </summary>
    private const string RootOwnedTarget = "/tmp";

    /// <summary>
    /// The enumeration <see cref="Dispose"/> walks the temp tree with. Shared with
    /// <see cref="Teardown_enumeration_does_not_reach_through_a_planted_directory_symlink"/> so that
    /// test pins the real object rather than a copy of it that could drift.
    /// </summary>
    private static readonly EnumerationOptions TeardownEnumeration = new()
    {
        RecurseSubdirectories = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
    };

    private readonly LocalSigningKeyFileSystem _sut = new();

    /// <summary>
    /// A fresh OS temp subdirectory per test, deliberately <strong>not</strong> resolved to its real
    /// path, so that the ancestor walk runs over the path the provider would really be handed.
    /// </summary>
    /// <remarks>
    /// On macOS this sits under <c>/var/folders/&lt;xx&gt;/&lt;yyy&gt;/T/</c>. The walk breaks at
    /// <c>/var/folders/&lt;xx&gt;</c>, which is root-owned but an ordinary directory — it never
    /// reaches the <c>/var</c> symlink. So the OS-temp test below proves the root-owned break
    /// fires; the <em>symlinked</em> ancestor carve-out is proven separately by
    /// <see cref="ReadKeyFileAsync_accepts_a_key_file_under_a_root_owned_symlinked_ancestor"/>,
    /// which uses the literal <c>/tmp</c>.
    /// </remarks>
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
    public void EnsureDirectorySafe_rejects_an_ancestor_that_is_a_symlink_to_a_root_owned_directory()
    {
        SkipUnlessRootOwnedTmpIsUsable();

        // Pins the trust break specifically. Reading it with stat() instead of lstat() follows the
        // link to root-owned /tmp, reports uid 0, and stops the walk before any other check runs —
        // an unprivileged attacker cannot plant a root-owned directory, but can freely plant their
        // own symlink pointing at one.
        var attackerSymlink = Path.Join(_tempDirectory, "looks-like-root-owned");
        PlantDirectorySymlink(attackerSymlink, RootOwnedTarget);

        var directory = Path.Join(attackerSymlink, $"zkda-chain-{Guid.NewGuid():N}");

        try
        {
            var act = () => _sut.EnsureDirectorySafe(directory);

            act.Should().Throw<ZeeKayDaConfigurationException>()
                .WithMessage("*is a symlink*");

            // The chain is validated before anything is created, so a rejected path leaves nothing
            // behind — least of all at a location the attacker chose by pointing the link.
            Directory.Exists(directory).Should().BeFalse();
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void EnsureDirectorySafe_rejects_an_ancestor_that_is_a_symlink_the_current_user_owns()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // Nothing about this one is attacker-planted: the link and its target both belong to the
        // current user. It is refused because a symlink is repointable, and because ReadKeyFileAsync
        // rejects any non-root-owned symlinked ancestor on the very next startup. Accepting it here
        // produced a configuration that started once, wrote a key, and could never start again.
        var realDirectory = Path.Join(_tempDirectory, "real-keys");
        Directory.CreateDirectory(realDirectory);

        var linkedDirectory = Path.Join(_tempDirectory, "linked-keys");
        PlantDirectorySymlink(linkedDirectory, realDirectory);

        var act = () => _sut.EnsureDirectorySafe(Path.Join(linkedDirectory, "signing-keys"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*is a symlink*");
    }

    [Fact]
    public void EnsureDirectorySafe_restricts_every_component_it_creates_to_the_owner()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // Regression: Directory.CreateDirectory applies the process umask to every component it
        // creates, and chmod'ing only the leaf leaves the intermediates at whatever the umask gave.
        // Under Ubuntu's default umask of 002 that is 0775 — so the provider created a
        // group-writable component and then rejected it on the next startup, an application that
        // started once, wrote a key, and could never start again. The Directory.CreateDirectory
        // overload taking a UnixFileMode does not help: it applies the mode only to the leaf.
        var ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        var intermediate = Path.Join(_tempDirectory, "dot-zeekayda");
        var leaf = Path.Join(intermediate, "signing-keys");

        _sut.EnsureDirectorySafe(leaf);

        GetUnixMode(intermediate).Should().Be(ownerOnly, "an intermediate component is part of the key path too");
        GetUnixMode(leaf).Should().Be(ownerOnly);

        // And the second startup — the whole point — must not reject what the first one created.
        var act = () => _sut.EnsureDirectorySafe(leaf);

        act.Should().NotThrow();
    }

    [Fact]
    public void EnsureDirectorySafe_rejects_an_ancestor_that_is_writable_by_group_or_other()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // Ownership alone does not stop replacement. POSIX grants rename and unlink from the
        // *directory's* write bit, not from ownership of what is inside it, so any group or world
        // member can move the signing key directory aside and have the provider mint a fresh key.
        var ancestor = Path.Join(_tempDirectory, "world-writable");
        Directory.CreateDirectory(ancestor);
        SetUnixMode(
            ancestor,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherWrite);

        var act = () => _sut.EnsureDirectorySafe(Path.Join(ancestor, "signing-keys"));

        // Names the offending component, so this cannot pass because some *other* ancestor of the
        // temp tree happened to be group-writable.
        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage($"*{ancestor}*writable by group or other*");
    }

    [Fact]
    public void EnsureDirectorySafe_accepts_a_sticky_world_writable_ancestor()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);
        Assert.SkipWhen(!Directory.Exists(RootOwnedTarget), $"{RootOwnedTarget} does not exist on this machine.");

        // The exemption that keeps the rule usable. /tmp is 1777: world-writable, but sticky, so a
        // user may only rename or unlink entries they own — exactly the property the check wants.
        // Without this carve-out every /tmp-hosted path is rejected, this suite's fixtures included.
        var directory = Path.Join(RootOwnedTarget, $"zkda-sticky-{Guid.NewGuid():N}");

        try
        {
            var act = () => _sut.EnsureDirectorySafe(directory);

            act.Should().NotThrow();
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void EnsureDirectorySafe_rejects_a_component_that_is_a_dangling_symlink()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // A dangling symlink is neither a file nor a directory, and an attacker can plant one
        // freely — pointing it at a path they will create later. It must not read as "absent" and
        // let the walk continue past it.
        var dangling = Path.Join(_tempDirectory, "points-nowhere");
        PlantDirectorySymlink(dangling, Path.Join(_tempDirectory, "does-not-exist"));

        var act = () => _sut.EnsureDirectorySafe(Path.Join(dangling, "signing-keys"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*exists but is not a directory*");
    }

    [Fact]
    public void EnsureDirectorySafe_rejects_a_leaf_that_exists_but_is_not_a_directory()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // The chain walk only ever sees ancestors, so the leaf needs its own check — without it a
        // file at the configured path surfaced as a raw IOException rather than a configuration
        // failure the operator can act on.
        var file = Path.Join(_tempDirectory, "signing-keys");
        File.WriteAllText(file, "");

        var act = () => _sut.EnsureDirectorySafe(file);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*exists but is not a directory*");
    }

    [Fact]
    public void EnsureDirectorySafe_rejects_a_path_whose_ancestor_exists_but_is_not_a_directory()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // The walk skips components that do not exist, so that it can validate the ancestors of a
        // directory it is about to create. A component that *does* exist but is not a directory must
        // not take that branch — that would be the one fail-open step in a fail-closed walk.
        var file = Path.Join(_tempDirectory, "not-a-directory");
        File.WriteAllText(file, "");

        var act = () => _sut.EnsureDirectorySafe(Path.Join(file, "signing-keys"));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .WithMessage("*exists but is not a directory*");
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
    [InlineData(UnixFileMode.GroupExecute)]
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

        // Asserts the *leaf* wording, not just the shared symlink_detected code, so this cannot
        // silently start passing on an ancestor rejection instead.
        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*Symlinks are not permitted for key files*");
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
        PlantDirectorySymlink(linkedDirectory, realDirectory);

        var act = () => _sut
            .ReadKeyFileAsync(Path.Join(linkedDirectory, KeyFileName), TestContext.Current.CancellationToken)
            .AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*resolves through a symlinked directory*");
    }

    [Fact]
    public async Task ReadKeyFileAsync_accepts_a_key_file_under_the_OS_temp_directory_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // Proves the root-owned break fires at all: before it existed, the walk ran past every
        // ancestor to the filesystem root and, on macOS, hit the /var symlink and rejected the key.
        // What it does NOT prove is the symlinked-ancestor carve-out — on macOS the walk breaks at
        // the root-owned but ordinary directory /var/folders/<xx> and never reaches /var, and on
        // Linux /tmp is not a symlink at all. That half is the next test's job.
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var act = () => _sut.ReadKeyFileAsync(keyPath, TestContext.Current.CancellationToken).AsTask();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ReadKeyFileAsync_accepts_a_key_file_under_a_root_owned_symlinked_ancestor()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);
        Assert.SkipWhen(!Directory.Exists(RootOwnedTarget), $"{RootOwnedTarget} does not exist on this machine.");

        // On macOS /tmp is itself a root-owned symlink to /private/tmp — exactly the ancestor shape
        // the carve-out exists for, and one no temp-subdirectory path reaches. On Linux /tmp is a
        // root-owned plain directory, so there this asserts only the root-owned break; the macOS
        // runner is what makes it a test of the symlink carve-out.
        var keyPath = Path.Join(RootOwnedTarget, $"zkda-dev-key-{Guid.NewGuid():N}.pem");
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        try
        {
            var act = () => _sut.ReadKeyFileAsync(keyPath, TestContext.Current.CancellationToken).AsTask();

            await act.Should().NotThrowAsync();
        }
        finally
        {
            File.Delete(keyPath);
        }
    }

    [Fact]
    public async Task ReadKeyFileAsync_rejects_a_non_root_owned_symlink_that_points_at_a_root_owned_directory()
    {
        SkipUnlessRootOwnedTmpIsUsable();

        // The bypass the trust anchor must close, and the reason it reads ownership with lstat()
        // rather than stat(). An unprivileged attacker cannot plant a root-owned directory, but can
        // freely plant their own symlink — owned by themselves — that merely points at one. stat()
        // follows the link and reports the target's root ownership, which would trust the
        // attacker's symlink and stop the walk; lstat() sees the link entry's own non-root owner
        // and keeps going, so the symlink is still rejected.
        //
        // Swapping GetLinkOwnerUid for a stat-based read in ValidateNoUntrustedSymlinkedAncestorUnix
        // leaves every other test in this class green. This is the one that fails.
        var attackerSymlink = Path.Join(_tempDirectory, "looks-like-root-owned");
        PlantDirectorySymlink(attackerSymlink, RootOwnedTarget);

        var fileName = $"zkda-lstat-regression-{Guid.NewGuid():N}.pem";
        var realKeyPath = Path.Join(RootOwnedTarget, fileName);
        await _sut.WriteKeyFileAsync(realKeyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        try
        {
            var act = () => _sut
                .ReadKeyFileAsync(Path.Join(attackerSymlink, fileName), TestContext.Current.CancellationToken)
                .AsTask();

            await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
                .WithMessage("*resolves through a symlinked directory*");
        }
        finally
        {
            File.Delete(realKeyPath);
        }
    }

    // ── The per-component decision, as a pure function ───────────────────────────────────────────

    // LocalSigningKeyFileSystem.JudgeComponent takes the four facts the walk reads from the file
    // system and returns a verdict, so the branches that need a second user or root to stage — and
    // which against real directories could only ever be reasoned about — are asserted here instead.

    private const uint Me = 501;
    private const uint SomeoneElse = 502;
    private const uint Root = 0;

    private static readonly UnixFileMode OwnerOnly =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    [Fact]
    public void JudgeComponent_accepts_an_owner_only_directory_owned_by_the_current_user() =>
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly, Me, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.Accept);

    [Fact]
    public void JudgeComponent_stops_the_walk_at_a_root_owned_directory() =>
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly, Root, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.TrustedRootOwned);

    [Fact]
    public void JudgeComponent_rejects_a_directory_owned_by_another_non_root_user() =>
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly, SomeoneElse, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.NotOwnedByCurrentUser);

    [Fact]
    public void JudgeComponent_rejects_a_symlink_the_current_user_owns() =>
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly, Me, Me, isSymlink: true)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.Symlink);

    [Fact]
    public void JudgeComponent_rejects_a_directory_whose_ownership_could_not_be_read() =>
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly, linkOwnerUid: null, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.OwnershipUndetermined);

    [Theory]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public void JudgeComponent_rejects_a_writable_directory_even_when_root_owns_it(UnixFileMode writeBit)
    {
        // The ordering the walk depends on: writability is judged BEFORE the root-owned trust break.
        // "root planted it" says nothing about who can rename it — POSIX grants rename and unlink
        // from the directory's own write bit — so a root-owned 0777 non-sticky directory is
        // replaceable by any local user. Judging ownership first would trust it unconditionally.
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly | writeBit, Root, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.WritableByOthers);
    }

    [Theory]
    [InlineData(UnixFileMode.GroupWrite)]
    [InlineData(UnixFileMode.OtherWrite)]
    public void JudgeComponent_exempts_a_sticky_writable_directory(UnixFileMode writeBit)
    {
        // /tmp at 1777. Sticky restricts rename and unlink to each entry's own owner, which is the
        // property the write-bit rule is actually after.
        LocalSigningKeyFileSystem.JudgeComponent(OwnerOnly | writeBit | UnixFileMode.StickyBit, Root, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.TrustedRootOwned);
    }

    [Fact]
    public void JudgeComponent_still_checks_ownership_of_a_sticky_writable_directory()
    {
        // The exemption skips the write-bit rule only. An attacker-owned entry inside a sticky
        // world-writable directory is still rejected on ownership.
        LocalSigningKeyFileSystem.JudgeComponent(
                OwnerOnly | UnixFileMode.OtherWrite | UnixFileMode.StickyBit, SomeoneElse, Me, isSymlink: false)
            .Should().Be(LocalSigningKeyFileSystem.ChainVerdict.NotOwnedByCurrentUser);
    }

    // ── This class's own teardown ────────────────────────────────────────────────────────────────

    [Fact]
    public void Teardown_enumeration_does_not_reach_through_a_planted_directory_symlink()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // Guards this class's own Dispose, not the code under test. Several tests here plant a
        // directory symlink to the real /tmp, and Dispose chmods everything its walk returns —
        // so if that walk ever follows a link again, the teardown re-permissions files outside its
        // temp tree, up to and including /private/tmp itself. That regression is a one-word edit to
        // the EnumerationOptions, and a comment is not a mitigation.
        var outside = Directory.CreateTempSubdirectory("zkda-teardown-outside-").FullName;
        File.WriteAllText(Path.Join(outside, "not-ours.txt"), "leave me alone");

        var nested = Path.Join(_tempDirectory, "nested");
        Directory.CreateDirectory(nested);
        PlantDirectorySymlink(Path.Join(nested, "link-out"), outside);

        try
        {
            var reached = Directory
                .EnumerateFiles(_tempDirectory, "*", TeardownEnumeration)
                .Select(Path.GetFileName)
                .ToList();

            reached.Should().NotContain("not-ours.txt");
        }
        finally
        {
            Directory.Delete(outside, recursive: true);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    // The three helpers below carry their own OperatingSystem.IsWindows() guard rather than relying
    // on the Assert.Skip* call at the top of each test: CA1416 cannot see that a skip aborts the
    // test, so a bare File.GetUnixFileMode/GetAccessControl call would fail the build. The
    // unreachable non-matching branch is inert — every caller is already skipped off-platform.

    /// <summary>
    /// Skips unless the machine can host the tests that plant a symlink at <see cref="RootOwnedTarget"/>.
    /// </summary>
    /// <remarks>
    /// The root check is the important one. As root, a planted symlink is <em>itself</em> root-owned,
    /// so the trust break fires legitimately and the test fails with a bare "no exception was thrown"
    /// that says nothing about <c>lstat</c> versus <c>stat</c> — someone debugging that in a root
    /// devcontainer could easily conclude the control is wrong and relax it.
    /// </remarks>
    private static void SkipUnlessRootOwnedTmpIsUsable()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");
        Assert.SkipWhen(!Directory.Exists(RootOwnedTarget), $"{RootOwnedTarget} does not exist on this machine.");
        Assert.SkipWhen(
            IsRunningAsRoot(),
            $"running as root: a root-planted symlink is itself root-owned, so the trust break fires legitimately and this test cannot tell lstat from stat.");
    }

    private static bool IsRunningAsRoot() =>
        !OperatingSystem.IsWindows() && PosixInterop.GetCurrentUid() == 0;

    /// <summary>
    /// Plants a directory symlink, skipping rather than failing where the platform will not create
    /// one without elevation — the same guard the sibling suite's equivalent tests carry.
    /// </summary>
    private static void PlantDirectorySymlink(string linkPath, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a directory symlink requires elevated privileges on this platform.");
        }
    }

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
                //
                // ReparsePoint MUST stay in AttributesToSkip, and the consequence of dropping it is
                // worse than "leaks into the link target". Two tests deliberately plant a directory
                // symlink to the real /tmp, and a plain SearchOption.AllDirectories walk follows it.
                // Measured, not assumed: the file walk chmod'd a file under the target from 0754 to
                // 0600 — and the *directory* walk returned the planted symlink itself, which
                // SetUnixFileMode follows, so it would have set /private/tmp from 1777 to 0700.
                // That is machine-wide: every user and every process on the box loses the temp
                // directory. Skipping reparse points stops both the match and the recursion, at any
                // depth. Directory.Delete(recursive) below already unlinks rather than follows, so
                // the planted links still get cleaned up.
                //
                // Note this deliberately replaces the default AttributesToSkip of Hidden | System
                // rather than adding to it: the SearchOption overloads skip nothing, and these tests
                // create dotted paths that must still be walked.
                foreach (var file in Directory.EnumerateFiles(_tempDirectory, "*", TeardownEnumeration))
                    File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);

                foreach (var directory in Directory.EnumerateDirectories(_tempDirectory, "*", TeardownEnumeration))
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
