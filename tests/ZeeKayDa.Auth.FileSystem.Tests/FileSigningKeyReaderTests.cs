using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.FileSystem.Tests.Fixtures;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct tests for <see cref="FileSigningKeyReader"/>'s best-effort, log-only environment-safety
/// warnings (world-writable parent directory) — the one part of the reader's behavior that is not
/// already exercised indirectly by <see cref="PemFileSigningJwtSigningServiceTests"/> and
/// <see cref="PfxFileSigningJwtSigningServiceTests"/> (which cover the hard-fail permission/symlink
/// checks via the full <c>IJwtSigningService</c> surface).
/// </summary>
public sealed class FileSigningKeyReaderTests
{
    [Fact]
    public async Task ReadPemTextAsync_logs_a_warning_when_the_parent_directory_is_world_writable_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "world-writable-directory detection uses the Unix permission model here.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", DateTimeOffset.UtcNow - TimeSpan.FromDays(1), DateTimeOffset.UtcNow + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        tempDir.MakeParentDirectoryWorldWritable();
        var logger = new CapturingSanitizingLogger<FileSigningKeyReader>();
        var reader = new FileSigningKeyReader(logger);

        await reader.ReadPemTextAsync(path, ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("world-writable"),
            "a world-writable parent directory lets another local user replace or redirect the signing key file");
    }

    [Fact]
    public async Task ReadPemTextAsync_does_not_warn_when_the_parent_directory_is_properly_secured()
    {
        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", DateTimeOffset.UtcNow - TimeSpan.FromDays(1), DateTimeOffset.UtcNow + TimeSpan.FromDays(365));
        var path = tempDir.WritePemFile("key.pem", certificate);
        var logger = new CapturingSanitizingLogger<FileSigningKeyReader>();
        var reader = new FileSigningKeyReader(logger);

        await reader.ReadPemTextAsync(path, ct);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning);
    }

    // ── Root-owned symlinked ancestor (regression: macOS /tmp -> /private/tmp etc.) ────────────────
    //
    // These two tests exercise FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix directly
    // against the OS temp directory instead of going through TempSigningKeyDirectory, which
    // deliberately resolves symlinked ancestors away (see its own remarks) precisely to avoid
    // measuring this behavior incidentally. Path.GetTempPath() is exactly the real-world path shape
    // that motivated the fix: on macOS it resolves under /tmp (root-owned symlink to /private/tmp).

    [Fact]
    public async Task ReadPemTextAsync_succeeds_for_a_file_under_the_OS_temp_directory_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "the root-owned-symlinked-ancestor exemption is Unix-only; Windows has no such OS convention to guard against.");

        var ct = TestContext.Current.CancellationToken;
        var rawTempDir = Directory.CreateTempSubdirectory("zkda-filesystem-tests-raw-");
        try
        {
            using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", DateTimeOffset.UtcNow - TimeSpan.FromDays(1), DateTimeOffset.UtcNow + TimeSpan.FromDays(365));
            var path = Path.Join(rawTempDir.FullName, "key.pem");
            await File.WriteAllTextAsync(path, TempSigningKeyDirectory.BuildCombinedPem(certificate), ct);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var reader = new FileSigningKeyReader(new CapturingSanitizingLogger<FileSigningKeyReader>());

            // Path.GetTempPath()-rooted paths must not be rejected merely because the OS resolves
            // /tmp (or /var, /etc) through a root-owned symlink — that is not an attacker-plantable
            // redirect, and this provider is the sole recommended signing provider for macOS (ADR
            // 0011 Amendment 7), where that convention is universal.
            await reader.ReadPemTextAsync(path, ct);
        }
        finally
        {
            rawTempDir.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task ReadPemTextAsync_still_throws_for_a_file_under_a_non_root_owned_symlinked_ancestor_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "directory-symlink semantics differ on Windows; the leaf-symlink case is already covered cross-platform elsewhere.");

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var realSubdirectory = Path.Join(tempDir.DirectoryPath, "real");
        Directory.CreateDirectory(realSubdirectory);
        var symlinkedSubdirectory = Path.Join(tempDir.DirectoryPath, "attacker-planted-link");

        try
        {
            Directory.CreateSymbolicLink(symlinkedSubdirectory, realSubdirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a directory symlink requires elevated privileges on this platform.");
            return;
        }

        using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", DateTimeOffset.UtcNow - TimeSpan.FromDays(1), DateTimeOffset.UtcNow + TimeSpan.FromDays(365));
        var path = Path.Join(symlinkedSubdirectory, "key.pem");
        await File.WriteAllTextAsync(Path.Join(realSubdirectory, "key.pem"), TempSigningKeyDirectory.BuildCombinedPem(certificate), ct);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(Path.Join(realSubdirectory, "key.pem"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var reader = new FileSigningKeyReader(new CapturingSanitizingLogger<FileSigningKeyReader>());

        // Unlike the OS temp directory above, this symlinked ancestor is owned by the current
        // (non-root) test process — exactly the attacker-plantable shape the ancestor-symlink check
        // must still reject.
        var act = async () => await reader.ReadPemTextAsync(path, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
    }

    [Fact]
    public async Task ReadPemTextAsync_still_throws_when_a_non_root_owned_symlink_points_at_a_root_owned_directory_on_Unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), "directory-symlink semantics differ on Windows; the leaf-symlink case is already covered cross-platform elsewhere.");

        // This is the exact bypass the ownership check must close: an unprivileged attacker cannot
        // plant a *root-owned* directory, but can freely plant their own symlink (owned by
        // themselves) that merely *points at* a root-owned directory like /tmp. Reading the
        // ownership via stat() (which follows the link) would wrongly see the target's root
        // ownership and trust the attacker's own symlink; lstat() (which does not follow it) sees
        // the symlink entry's real, non-root owner and still rejects it.
        //
        // Deliberately the literal path "/tmp", NOT Path.GetTempPath(): on macOS, Path.GetTempPath()
        // resolves to a *user-owned* per-process directory under /var/folders/..., not to /tmp
        // itself — pointing the attacker symlink there would make this test collapse into the same
        // safe case the sibling test above already covers, silently passing under both the buggy
        // stat()-based code and the lstat()-based fix alike (caught in security re-review). The
        // literal "/tmp" is root-owned (mode 1777, owner root) by POSIX/FHS convention on every
        // mainstream Unix, including every GitHub Actions macOS/Linux runner this suite runs on, and
        // does not depend on TMPDIR or any other environment-specific redirection the way
        // Path.GetTempPath() does.
        const string RootOwnedTarget = "/tmp";

        var ct = TestContext.Current.CancellationToken;
        using var tempDir = new TempSigningKeyDirectory();
        var attackerSymlink = Path.Join(tempDir.DirectoryPath, "looks-like-root-owned");

        try
        {
            Directory.CreateSymbolicLink(attackerSymlink, RootOwnedTarget);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Assert.Skip("Creating a directory symlink requires elevated privileges on this platform.");
            return;
        }

        var leafFileName = $"zkda-lstat-regression-{Guid.NewGuid():N}.pem";
        var path = Path.Join(attackerSymlink, leafFileName);
        var realLeafPath = Path.Join(RootOwnedTarget, leafFileName);
        try
        {
            using var certificate = TestCertificateFactory.CreateRsaSelfSigned("test", DateTimeOffset.UtcNow - TimeSpan.FromDays(1), DateTimeOffset.UtcNow + TimeSpan.FromDays(365));
            await File.WriteAllTextAsync(realLeafPath, TempSigningKeyDirectory.BuildCombinedPem(certificate), ct);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(realLeafPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var reader = new FileSigningKeyReader(new CapturingSanitizingLogger<FileSigningKeyReader>());

            var act = async () => await reader.ReadPemTextAsync(path, ct);

            var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
            exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.file_signing.symlink_detected");
        }
        finally
        {
            File.Delete(realLeafPath);
        }
    }
}
