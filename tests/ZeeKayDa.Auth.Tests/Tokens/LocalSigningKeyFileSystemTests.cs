using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="LocalSigningKeyFileSystem"/> against a real file system, because its entire
/// job <em>is</em> real file-system interaction: the <c>0700</c>/<c>0600</c> modes and the symlink
/// refusal are the security-critical part of the development signing key provider.
/// </summary>
/// <remarks>
/// <see cref="DevelopmentSigningKeySourceTests"/> covers the same failure codes through fakes, which
/// only prove that <c>DevelopmentSigningKeySource</c> propagates an exception a fake threw. These
/// prove the real checks fire. Platform-specific assertions are gated with <c>Assert.SkipWhen</c> so
/// each CI runner proves its own half: POSIX modes on Linux/macOS, the non-inherited ACL on Windows.
/// </remarks>
public sealed class LocalSigningKeyFileSystemTests : IDisposable
{
    private const string KeyFileName = "dev-signing-key.pem";

    private const string SamplePem =
        "-----BEGIN PRIVATE KEY-----\nc2lnbmluZy1rZXktbWF0ZXJpYWw=\n-----END PRIVATE KEY-----\n";

    private const string RequiresUnixReason =
        "POSIX file-mode bits are the Unix permission model.";

    private const string RequiresWindowsReason =
        "non-inherited ACL enforcement is the Windows permission model.";

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

    /// <summary>A fresh OS temp subdirectory per test.</summary>
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
    public void EnsureDirectorySafe_accepts_a_directory_under_a_group_writable_ancestor()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        // Deliberate: ancestors are not checked for a development key, which only works in
        // Development. The production file provider still refuses this shape.
        var ancestor = Path.Join(_tempDirectory, "shared");
        Directory.CreateDirectory(ancestor);
        SetUnixMode(ancestor, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute);

        var act = () => _sut.EnsureDirectorySafe(Path.Join(ancestor, "signing-keys"));

        act.Should().NotThrow();
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
    public async Task WriteKeyFileAsync_creates_the_lock_file_readable_only_by_the_owner_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        GetUnixMode(keyPath + ".lock").Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public async Task WriteKeyFileAsync_applies_a_non_inherited_owner_only_acl_on_Windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        AssertOwnerOnlyProtectedAcl(keyPath);
    }

    [Fact]
    public async Task WriteKeyFileAsync_writes_the_key_at_the_key_path()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        File.ReadAllText(keyPath).Should().Be(SamplePem);
    }

    [Fact]
    public async Task WriteKeyFileAsync_leaves_an_existing_key_file_untouched()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        await _sut.WriteKeyFileAsync(keyPath, "another key".AsMemory(), TestContext.Current.CancellationToken);

        File.ReadAllText(keyPath).Should().Be(SamplePem);
    }

    [Fact]
    public async Task WriteKeyFileAsync_leaves_no_pending_file_behind_whether_it_won_or_lost()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);

        await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);
        await _sut.WriteKeyFileAsync(keyPath, "another key".AsMemory(), TestContext.Current.CancellationToken);

        Directory.GetFiles(_tempDirectory, "*.pending").Should().BeEmpty();
    }

    [Fact]
    public async Task WriteKeyFileAsync_leaves_neither_a_pending_file_nor_a_key_when_cancelled()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        var act = async () => await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), cancelled.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        Directory.GetFiles(_tempDirectory, "*.pending").Should().BeEmpty();
        File.Exists(keyPath).Should().BeFalse();
    }

    [Fact]
    public async Task WriteKeyFileAsync_refuses_a_key_path_that_is_a_directory()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        Directory.CreateDirectory(keyPath);

        var act = async () => await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("signing.dev_keys.key_path_not_a_file");
        Directory.EnumerateFileSystemEntries(keyPath).Should().BeEmpty();
        Directory.GetFiles(_tempDirectory, "*.pending").Should().BeEmpty();
    }

    [Fact]
    public async Task WriteKeyFileAsync_refuses_a_dangling_symlink_at_the_key_path_without_writing_through_it()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var target = Path.Join(_tempDirectory, "elsewhere.pem");
        File.CreateSymbolicLink(keyPath, target);

        var act = async () => await _sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("signing.dev_keys.key_path_not_a_file");
        File.Exists(target).Should().BeFalse("nothing may be written through the link");
        Directory.GetFiles(_tempDirectory, "*.pending").Should().BeEmpty();
    }

    [Fact]
    public void FileExists_reports_a_dangling_symlink_as_absent()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        File.CreateSymbolicLink(keyPath, Path.Join(_tempDirectory, "elsewhere.pem"));

        _sut.FileExists(keyPath).Should().BeFalse();
    }

    [Fact]
    public async Task WriteKeyFileAsync_checks_for_an_existing_key_only_once_it_holds_the_lock()
    {
        // The key created by whoever held the lock must be found, not replaced: checking before
        // taking the lock is the check-then-rename race the lock exists to close.
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var published = false;
        var sut = new LocalSigningKeyFileSystem
        {
            PublishPending = (pending, target) =>
            {
                published = true;
                LocalSigningKeyFileSystem.Publish(pending, target);
            },
        };
        Task write;
        Task finishedFirst;
        await using (new FileStream(keyPath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            write = sut.WriteKeyFileAsync(keyPath, "another key".AsMemory(), TestContext.Current.CancellationToken).AsTask();
            finishedFirst = await Task.WhenAny(write, Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken));
            await File.WriteAllTextAsync(keyPath, SamplePem, TestContext.Current.CancellationToken);
        }

        finishedFirst.Should().NotBeSameAs(write, "a host must wait while another holds the lock");
        await write;
        published.Should().BeFalse("a host that finds the key under the lock never tries to publish its own");
        File.ReadAllText(keyPath).Should().Be(SamplePem);
    }

    [Fact]
    public async Task WriteKeyFileAsync_publishes_the_key_only_once_it_is_fully_written()
    {
        // Large enough to span many write buffers, so a file published before its writer flushed
        // and closed it would be seen short at the instant of publication.
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var pem = new string('k', 256 * 1024);
        string? atPublication = null;
        var sut = new LocalSigningKeyFileSystem
        {
            PublishPending = (pending, target) =>
            {
                atPublication = File.ReadAllText(pending);
                LocalSigningKeyFileSystem.Publish(pending, target);
            },
        };

        await sut.WriteKeyFileAsync(keyPath, pem.AsMemory(), TestContext.Current.CancellationToken);

        atPublication.Should().Be(pem);
    }

    [Fact]
    public async Task WriteKeyFileAsync_fails_with_lock_timeout_when_the_lock_is_never_released()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var sut = new LocalSigningKeyFileSystem { LockTimeout = TimeSpan.FromMilliseconds(200) };
        await using var otherHostsLock = new FileStream(keyPath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        var act = async () => await sut.WriteKeyFileAsync(keyPath, SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        thrown.Which.AggregatedFailures.Should().ContainSingle().Which.Code.Should().Be("signing.dev_keys.lock_timeout");
        thrown.Which.InnerException.Should().BeAssignableTo<IOException>();
        File.Exists(keyPath).Should().BeFalse();
    }

    [Fact]
    public async Task WriteKeyFileAsync_racers_all_read_one_whole_key()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var ct = TestContext.Current.CancellationToken;
        var pems = Enumerable.Range(0, 8).Select(i => new string((char)('a' + i), 256 * 1024)).ToArray();

        var reads = await Task.WhenAll(pems.Select(pem => Task.Run(async () =>
        {
            await _sut.WriteKeyFileAsync(keyPath, pem.AsMemory(), ct);
            using var content = await _sut.ReadKeyFileAsync(keyPath, ct);
            return Encoding.UTF8.GetString(content.Bytes);
        }, ct)));

        pems.Should().Contain(reads[0], "the key on disk is one racer's whole key");
        reads.Should().AllBe(reads[0]);
    }

    [Fact]
    public void Publish_keeps_the_existing_key_when_another_host_got_there_first()
    {
        var keyPath = Path.Join(_tempDirectory, KeyFileName);
        var pending = Path.Join(_tempDirectory, "pending");
        File.WriteAllText(keyPath, SamplePem);
        File.WriteAllText(pending, "another key");

        LocalSigningKeyFileSystem.Publish(pending, keyPath);

        File.ReadAllText(keyPath).Should().Be(SamplePem);
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
    public async Task ReadKeyFileAsync_accepts_a_key_file_reached_through_a_symlinked_ancestor()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // Deliberate: ancestors are not walked for a development key, which only works in
        // Development. The production file provider still refuses this shape.
        var realDirectory = Path.Join(_tempDirectory, "real-keys");
        Directory.CreateDirectory(realDirectory);
        await _sut.WriteKeyFileAsync(
            Path.Join(realDirectory, KeyFileName), SamplePem.AsMemory(), TestContext.Current.CancellationToken);

        var linkedDirectory = Path.Join(_tempDirectory, "linked-keys");
        PlantDirectorySymlink(linkedDirectory, realDirectory);

        var act = () => _sut
            .ReadKeyFileAsync(Path.Join(linkedDirectory, KeyFileName), TestContext.Current.CancellationToken)
            .AsTask();

        await act.Should().NotThrowAsync();
    }

    // ── This class's own teardown ────────────────────────────────────────────────────────────────

    [Fact]
    public void Teardown_enumeration_does_not_reach_through_a_planted_directory_symlink()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "creating a symlink on Windows requires elevation.");

        // Guards this class's own Dispose, not the code under test. A test here plants a directory
        // symlink, and Dispose chmods everything its walk returns — so if that walk ever follows a
        // link, the teardown re-permissions files outside its temp tree. That regression is a one-word edit to
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
