using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentJwtSigningServiceTests : IDisposable
{
    private readonly List<string> _tempDirs = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            try { Directory.Delete(dir, recursive: true); }
            catch { /* best effort */ }
        }
    }

    private string CreateTempDir()
    {
        var path = Path.Combine(Path.GetTempPath(), $"zk-dev-signing-test-{Guid.NewGuid():N}");
        _tempDirs.Add(path);
        return path;
    }

    private static DevelopmentJwtSigningService BuildEphemeral()
    {
        var options = new DevelopmentSigningKeyOptions
        {
            PersistToDirectory = null, // ephemeral
        };
        return new DevelopmentJwtSigningService(
            Options.Create(options),
            new FakeTimeProvider());
    }

    private DevelopmentJwtSigningService BuildPersisted(string? directory = null)
    {
        var dir = directory ?? CreateTempDir();
        var options = new DevelopmentSigningKeyOptions
        {
            PersistToDirectory = dir,
        };
        return new DevelopmentJwtSigningService(
            Options.Create(options),
            new FakeTimeProvider());
    }

    // ── Ephemeral key generation ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Ephemeral_key_is_generated_successfully()
    {
        await using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
        keys[0].Kid.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Ephemeral_key_uses_RS256_algorithm()
    {
        await using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle().Which.Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task Ephemeral_key_is_at_least_3072_bits()
    {
        await using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        var key = keys[0];
        key.KeyType.Should().Be(SigningKeyType.Rsa);
        var modulus = key.RsaPublicParameters!.Value.Modulus!;
        var bitLength = modulus.Length * 8;
        bitLength.Should().BeGreaterThanOrEqualTo(3072);
    }

    [Fact]
    public async Task Ephemeral_SignAsync_produces_valid_result()
    {
        await using var sut = BuildEphemeral();
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"test"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.Kid.Should().NotBeNullOrEmpty();
        result.Algorithm.Should().Be(SigningAlgorithm.RS256);
        result.HeaderSegment.IsEmpty.Should().BeFalse();
        result.SignatureSegment.IsEmpty.Should().BeFalse();
    }

    // ── Persistence round-trip ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Persisted_key_file_is_created_on_first_startup()
    {
        var dir = CreateTempDir();
        await using var sut = BuildPersisted(dir);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        var keyFile = Path.Combine(dir, "dev-signing-key.pem");
        File.Exists(keyFile).Should().BeTrue("the key file must be written on first startup");
    }

    [Fact]
    public async Task Persisted_key_has_same_kid_across_restarts()
    {
        var dir = CreateTempDir();
        var ct = TestContext.Current.CancellationToken;

        string firstKid;
        await using (var first = BuildPersisted(dir))
        {
            var keys = await first.GetSigningKeysAsync(ct);
            firstKid = keys[0].Kid;
        }

        await using (var second = BuildPersisted(dir))
        {
            var keys = await second.GetSigningKeysAsync(ct);
            keys[0].Kid.Should().Be(firstKid, "the kid must be stable across restarts when persisted");
        }
    }

    [Fact]
    public async Task Tokens_signed_in_first_session_validate_with_keys_from_second_session()
    {
        var dir = CreateTempDir();
        var ct = TestContext.Current.CancellationToken;

        string kid;
        string signedPayload;

        await using (var first = BuildPersisted(dir))
        {
            var keys = await first.GetSigningKeysAsync(ct);
            kid = keys[0].Kid;

            var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
            var result = await first.SignAsync(payload, ct);

            var header = Encoding.ASCII.GetString(result.HeaderSegment.Span);
            var payloadStr = Encoding.ASCII.GetString(payload);
            var signature = Encoding.ASCII.GetString(result.SignatureSegment.Span);
            signedPayload = $"{header}.{payloadStr}.{signature}";
        }

        await using (var second = BuildPersisted(dir))
        {
            var keys = await second.GetSigningKeysAsync(ct);
            keys[0].Kid.Should().Be(kid);

            var rsaParams = keys[0].RsaPublicParameters!.Value;
            using var rsa = RSA.Create();
            rsa.ImportParameters(rsaParams);

            var parts = signedPayload.Split('.');
            var signingInput = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
            var signature = DecodeBase64Url(Encoding.UTF8.GetBytes(parts[2]));

            var valid = rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            valid.Should().BeTrue("tokens from the first session must validate with keys from the second session");
        }
    }

    // ── File permission enforcement (Unix only) ───────────────────────────────────────────────────

    [Fact]
    public async Task Directory_with_too_permissive_mode_fails_closed_on_unix()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckDirectoryTooPermissiveOnUnix();
#pragma warning restore CA1416
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckDirectoryTooPermissiveOnUnix()
    {
        var dir = CreateTempDir();
        Directory.CreateDirectory(dir);
        // Set group-readable permissions on the directory.
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead);
        var ct = TestContext.Current.CancellationToken;

        await using var sut = BuildPersisted(dir);

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*directory_too_permissive*");
    }

    [Fact]
    public async Task Persisted_key_file_has_permissions_0600_on_unix()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckFilePermissionsOnUnix();
#pragma warning restore CA1416
    }

    [Fact]
    public async Task Loading_key_file_with_group_readable_permissions_fails_closed()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckGroupReadablePermissionsOnUnix();
#pragma warning restore CA1416
    }

    [Fact]
    public async Task Loading_key_file_that_is_a_symlink_fails_closed()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckSymlinkDetectionOnUnix();
#pragma warning restore CA1416
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckFilePermissionsOnUnix()
    {
        var dir = CreateTempDir();
        await using var sut = BuildPersisted(dir);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        var keyFile = Path.Combine(dir, "dev-signing-key.pem");
        var mode = File.GetUnixFileMode(keyFile);

        var allowedBits = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        (mode & ~allowedBits).Should().Be(0, "key file must have exactly 0600 permissions");
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckGroupReadablePermissionsOnUnix()
    {
        var dir = CreateTempDir();
        var ct = TestContext.Current.CancellationToken;

        // Create the file first with correct permissions.
        await using (var create = BuildPersisted(dir))
            await create.GetSigningKeysAsync(ct);

        // Widen permissions to group-readable.
        var keyFile = Path.Combine(dir, "dev-signing-key.pem");
        File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        await using var sut = BuildPersisted(dir);

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*file_too_permissive*");
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckSymlinkDetectionOnUnix()
    {
        var dir = CreateTempDir();
        var ct = TestContext.Current.CancellationToken;

        // Create a legitimate key file in a separate dir.
        var realDir = CreateTempDir();
        await using (var create = BuildPersisted(realDir))
            await create.GetSigningKeysAsync(ct);

        // Create the target directory with correct permissions and a symlink inside.
        Directory.CreateDirectory(dir);
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var symlink = Path.Combine(dir, "dev-signing-key.pem");
        var target = Path.Combine(realDir, "dev-signing-key.pem");
        File.CreateSymbolicLink(symlink, target);

        await using var sut = BuildPersisted(dir);

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*symlink_detected*");
    }

    // ── Error handling ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Loading_corrupt_pem_file_disposes_rsa_and_rethrows()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckCorruptPemFileOnUnix();
#pragma warning restore CA1416
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckCorruptPemFileOnUnix()
    {
        var dir = CreateTempDir();
        Directory.CreateDirectory(dir);
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var keyFile = Path.Combine(dir, "dev-signing-key.pem");
        File.WriteAllText(keyFile, "this is not a valid PEM");
        File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var ct = TestContext.Current.CancellationToken;
        await using var sut = BuildPersisted(dir);

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<Exception>("corrupt PEM must cause an exception");
    }

    [Fact]
    public async Task Write_failure_during_key_generation_disposes_rsa_and_rethrows()
    {
        Assert.SkipWhen(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Unix-only test");
#pragma warning disable CA1416 // call is guarded by Assert.SkipWhen above
        await CheckWriteFailureOnUnix();
#pragma warning restore CA1416
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private async Task CheckWriteFailureOnUnix()
    {
        var dir = CreateTempDir();
        Directory.CreateDirectory(dir);
        // 0500 — user read+execute only, no write.  Directory passes validation (no group/other bits)
        // but writing a new file inside it will be denied.
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);

        var ct = TestContext.Current.CancellationToken;
        await using var sut = BuildPersisted(dir);

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<Exception>("failure to write the key file must bubble out");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static string Base64UrlEncodeString(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var encoded = new byte[Base64Url.GetEncodedLength(bytes.Length)];
        Base64Url.EncodeToUtf8(bytes, encoded);
        return Encoding.ASCII.GetString(encoded);
    }

    private static byte[] DecodeBase64Url(byte[] encoded)
    {
        var decoded = new byte[Base64Url.GetMaxDecodedLength(encoded.Length)];
        Base64Url.DecodeFromUtf8(encoded, decoded, out _, out var written);
        return decoded[..written];
    }
}
