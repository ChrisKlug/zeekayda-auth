using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class DevelopmentJwtSigningServiceTests
{
    // ── In-memory fake file system ────────────────────────────────────────────────────────────────

    private sealed class InMemorySigningKeyFileSystem : ISigningKeyFileSystem
    {
        private readonly Dictionary<string, string> _files = new(StringComparer.Ordinal);
        private readonly HashSet<string> _directories = new(StringComparer.Ordinal);

        public bool DirectoryTooPermissive { get; set; }
        public bool FileTooPermissive { get; set; }
        public bool FileIsSymlink { get; set; }

        public void EnsureDirectorySafe(string directory)
        {
            if (DirectoryTooPermissive)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.directory_too_permissive",
                        $"Signing key directory '{directory}' has permissions broader than 0700."));
            }

            _directories.Add(directory);
        }

        public void WriteKeyFile(string keyPath, string pem)
        {
            _files[keyPath] = pem;
        }

        public string ReadKeyFile(string keyPath)
        {
            if (FileIsSymlink)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.symlink_detected",
                        $"Signing key path '{keyPath}' resolves through a symlink."));
            }

            if (FileTooPermissive)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.dev_keys.file_too_permissive",
                        $"Signing key file '{keyPath}' has permissions broader than 0600."));
            }

            return _files[keyPath];
        }

        public bool FileExists(string path) => _files.ContainsKey(path);

        public void SeedFile(string path, string content) => _files[path] = content;
    }

    private static DevelopmentJwtSigningService BuildEphemeral(
        ISigningKeyFileSystem? fs = null)
    {
        var options = new DevelopmentSigningKeyOptions
        {
            PersistToDirectory = null,
        };
        return new DevelopmentJwtSigningService(
            Options.Create(options),
            new FakeTimeProvider(),
            fs ?? new InMemorySigningKeyFileSystem());
    }

    private static DevelopmentJwtSigningService BuildPersisted(
        string directory,
        ISigningKeyFileSystem? fs = null)
    {
        var options = new DevelopmentSigningKeyOptions
        {
            PersistToDirectory = directory,
        };
        return new DevelopmentJwtSigningService(
            Options.Create(options),
            new FakeTimeProvider(),
            fs ?? new InMemorySigningKeyFileSystem());
    }

    // ── Constructor validation ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new DevelopmentJwtSigningService(
            null!,
            new FakeTimeProvider(),
            new InMemorySigningKeyFileSystem());

        // The base class JwtSigningService<TOptions> checks "options" before our guard fires.
        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_when_fileSystem_is_null()
    {
        var options = Options.Create(new DevelopmentSigningKeyOptions());

        var act = () => new DevelopmentJwtSigningService(
            options,
            new FakeTimeProvider(),
            null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("fileSystem");
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
    public async Task Persisted_key_file_is_written_on_first_startup()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem();
        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        var keyPath = Path.Join(dir, "dev-signing-key.pem");
        fs.FileExists(keyPath).Should().BeTrue("the key file must be written on first startup");
    }

    [Fact]
    public async Task Persisted_key_file_content_is_valid_pem()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem();
        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        var keyPath = Path.Join(dir, "dev-signing-key.pem");
        var pem = fs.ReadKeyFile(keyPath);
        pem.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----");
    }

    [Fact]
    public async Task Persisted_key_has_same_kid_across_restarts()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem();
        var ct = TestContext.Current.CancellationToken;

        string firstKid;
        await using (var first = BuildPersisted(dir, fs))
        {
            var keys = await first.GetSigningKeysAsync(ct);
            firstKid = keys[0].Kid;
        }

        await using (var second = BuildPersisted(dir, fs))
        {
            var keys = await second.GetSigningKeysAsync(ct);
            keys[0].Kid.Should().Be(firstKid, "the kid must be stable across restarts when persisted");
        }
    }

    [Fact]
    public async Task Tokens_signed_in_first_session_validate_with_keys_from_second_session()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem();
        var ct = TestContext.Current.CancellationToken;

        string kid;
        string signedPayload;

        await using (var first = BuildPersisted(dir, fs))
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

        await using (var second = BuildPersisted(dir, fs))
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

    // ── Directory permission enforcement ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Directory_with_too_permissive_mode_fails_closed()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem { DirectoryTooPermissive = true };
        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*directory_too_permissive*");
    }

    // ── File permission enforcement ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Loading_key_file_with_too_permissive_permissions_fails_closed()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem { FileTooPermissive = true };

        // Seed an existing file so the code tries to read rather than write.
        var keyPath = Path.Join(dir, "dev-signing-key.pem");
        fs.SeedFile(keyPath, "dummy content");

        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*file_too_permissive*");
    }

    // ── Symlink detection ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Loading_key_file_that_is_a_symlink_fails_closed()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem { FileIsSymlink = true };

        var keyPath = Path.Join(dir, "dev-signing-key.pem");
        fs.SeedFile(keyPath, "dummy content");

        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*symlink_detected*");
    }

    // ── Error handling ────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Loading_corrupt_pem_file_throws()
    {
        const string dir = "/fake/keys";
        var fs = new InMemorySigningKeyFileSystem();

        // Seed a file with invalid PEM content.
        var keyPath = Path.Join(dir, "dev-signing-key.pem");
        fs.SeedFile(keyPath, "this is not a valid PEM");

        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<Exception>("corrupt PEM must cause an exception");
    }

    [Fact]
    public async Task Write_failure_during_key_generation_rethrows()
    {
        const string dir = "/fake/keys";
        var fs = new ThrowOnWriteFileSystem();

        await using var sut = BuildPersisted(dir, fs);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<IOException>("failure to write the key file must bubble out");
    }

    private sealed class ThrowOnWriteFileSystem : ISigningKeyFileSystem
    {
        public void EnsureDirectorySafe(string directory) { }
        public void WriteKeyFile(string keyPath, string pem) => throw new IOException("Simulated write failure.");
        public string ReadKeyFile(string keyPath) => throw new InvalidOperationException("Should not be called.");
        public bool FileExists(string path) => false;
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
