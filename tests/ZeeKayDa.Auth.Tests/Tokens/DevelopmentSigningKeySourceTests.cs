using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="DevelopmentSigningKeySource"/>: the single generated or persisted
/// development key it reports, the signer it lends for that key exactly once, the environment gate
/// it enforces on every read, and the fail-closed file checks it inherits from
/// <see cref="IDevelopmentSigningKeyFileSystem"/>.
/// </summary>
public sealed class DevelopmentSigningKeySourceTests
{
    private const string KeyFileName = "dev-signing-key.pem";

    private const string PersistDirectory = "/fake/keys";

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class InMemorySigningKeyFileSystem : IDevelopmentSigningKeyFileSystem
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

        public ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
        {
            _files[keyPath] = new string(pem.Span);
            return ValueTask.CompletedTask;
        }

        public ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken)
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

            return ValueTask.FromResult(new KeyFileContent(Encoding.UTF8.GetBytes(_files[keyPath])));
        }

        public bool FileExists(string path) => _files.ContainsKey(path);

        public string ReadRaw(string path) => _files[path];

        public void SeedFile(string path, string content) => _files[path] = content;
    }

    private sealed class ThrowOnWriteFileSystem : IDevelopmentSigningKeyFileSystem
    {
        public void EnsureDirectorySafe(string directory)
        {
        }

        public ValueTask WriteKeyFileAsync(string keyPath, ReadOnlyMemory<char> pem, CancellationToken cancellationToken)
            => throw new IOException("Simulated write failure.");

        public ValueTask<KeyFileContent> ReadKeyFileAsync(string keyPath, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Should not be called.");

        public bool FileExists(string path) => false;
    }

    // ── Constructor validation ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new DevelopmentSigningKeySource(null!, new InMemorySigningKeyFileSystem());

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_when_fileSystem_is_null()
    {
        var act = () => new DevelopmentSigningKeySource(
            Options.Create(new DevelopmentSigningKeyOptions()), null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("fileSystem");
    }

    // ── Ephemeral key generation ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReadAsync_reports_exactly_one_key_and_signs_with_it()
    {
        using var sut = BuildEphemeral();

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.Keys.Should().ContainSingle();
        set.SigningKey.Should().BeSameAs(set.Keys[0]);
    }

    [Fact]
    public async Task ReadAsync_reports_the_key_under_RS256()
    {
        using var sut = BuildEphemeral();

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.SigningKey.Algorithm.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task ReadAsync_generates_a_key_of_at_least_3072_bits()
    {
        using var sut = BuildEphemeral();

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.SigningKey.PublicKey.KeyType.Should().Be(SigningKeyType.Rsa);
        using var rsa = RSA.Create();
        rsa.ImportParameters(set.SigningKey.PublicKey.RsaPublicParameters!.Value);
        rsa.KeySize.Should().BeGreaterThanOrEqualTo(3072);
    }

    [Fact]
    public async Task ReadAsync_reports_the_development_key_as_never_expiring()
    {
        using var sut = BuildEphemeral();

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.SigningKey.ExpiresAt.Should().BeNull(
            "a development key's lifetime is the process's, not a certificate's");
    }

    [Fact]
    public async Task ReadAsync_reports_a_stable_source_key_id()
    {
        using var sut = BuildEphemeral();

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.SigningKey.Id.Should().Be(new SourceKeyId("development"));
    }

    // ── Lending the signer ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSignerAsync_lends_a_signer_for_the_reported_key()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;
        var set = await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(set.SigningKey.Id, ct);
        var signature = await signer.SignAsync("payload"u8.ToArray(), ct);

        signer.Algorithm.Should().Be(SigningAlgorithm.RS256);
        SigningAlgorithms.Verify(
                SigningAlgorithm.RS256, set.SigningKey.PublicKey, "payload"u8, signature.Span)
            .Should().BeTrue("the lent signer must hold the private half of the reported key");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_the_key_has_already_been_lent()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;
        var set = await sut.ReadAsync(ct);
        using var first = await sut.CreateSignerAsync(set.SigningKey.Id, ct);

        var act = () => sut.CreateSignerAsync(set.SigningKey.Id, ct).AsTask();

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*no pending private key is available*");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_asked_for_a_key_this_source_never_reported()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;
        await sut.ReadAsync(ct);

        var act = () => sut.CreateSignerAsync(new SourceKeyId("someone-elses-key"), ct).AsTask();

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*which this source did not report*");
    }

    [Fact]
    public async Task CreateSignerAsync_throws_when_ReadAsync_has_never_run()
    {
        using var sut = BuildEphemeral();

        var act = () => sut.CreateSignerAsync(
            new SourceKeyId("development"), TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*no pending private key is available*");
    }

    // ── Served through the ring ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Development_keys_are_served_through_the_ring_and_can_sign_a_jws()
    {
        var ct = TestContext.Current.CancellationToken;
        using var ring = new StaticSigningKeyRing(BuildEphemeral(), new FakeTimeProvider());
        await ((ISigningKeyRing)ring).InitializeAsync(ct);

        var outcome = await ring.SignAsync(
            """{"sub":"alice"}"""u8.ToArray(),
            static (_, state) => state,
            ct);

        ring.Current.Published.Should().ContainSingle();
        outcome.Key.Kid.Should().Be(ring.Current.SigningKey.Kid);
        SigningAlgorithms.Verify(
                outcome.Key.Algorithm, outcome.Key.PublicKey, outcome.SigningInput.Span, outcome.Signature.Span)
            .Should().BeTrue();
    }

    // ── Persistence ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Persisted_key_file_is_written_on_first_read()
    {
        var fs = new InMemorySigningKeyFileSystem();
        using var sut = BuildPersisted(fs);

        await sut.ReadAsync(TestContext.Current.CancellationToken);

        fs.FileExists(Path.Join(PersistDirectory, KeyFileName)).Should().BeTrue();
    }

    [Fact]
    public async Task Persisted_key_file_holds_an_importable_private_key()
    {
        var fs = new InMemorySigningKeyFileSystem();
        using var sut = BuildPersisted(fs);

        await sut.ReadAsync(TestContext.Current.CancellationToken);

        var pem = fs.ReadRaw(Path.Join(PersistDirectory, KeyFileName));
        using var rsa = RSA.Create();
        var act = () => rsa.ImportFromPem(pem);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task Persisted_key_is_the_same_key_across_restarts()
    {
        var fs = new InMemorySigningKeyFileSystem();
        var ct = TestContext.Current.CancellationToken;

        byte[] firstModulus;
        using (var first = BuildPersisted(fs))
        {
            var set = await first.ReadAsync(ct);
            firstModulus = set.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus!;
        }

        using var second = BuildPersisted(fs);
        var secondSet = await second.ReadAsync(ct);

        secondSet.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(firstModulus,
                "a persisted key must survive a restart, or tokens issued before it would stop verifying");
    }

    // ── Disposal of an unclaimed key ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Dispose_disposes_the_key_when_CreateSignerAsync_never_claimed_it()
    {
        var sut = BuildEphemeral();
        await sut.ReadAsync(TestContext.Current.CancellationToken);
        var pendingKey = PendingPrivateKeyOf(sut);
        pendingKey.Should().NotBeNull("ReadAsync must have stashed the generated key");

        sut.Dispose();

        var act = () => pendingKey!.ExportParameters(true);
        act.Should().Throw<ObjectDisposedException>(
            "an unclaimed private key must be disposed at shutdown, not leaked until GC finalization");
    }

    [Fact]
    public async Task Dispose_leaves_the_key_alone_once_CreateSignerAsync_claimed_it()
    {
        var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;
        var set = await sut.ReadAsync(ct);
        using var signer = await sut.CreateSignerAsync(set.SigningKey.Id, ct);

        sut.Dispose();

        var signature = await signer.SignAsync("payload"u8.ToArray(), ct);
        SigningAlgorithms.Verify(
                SigningAlgorithm.RS256, set.SigningKey.PublicKey, "payload"u8, signature.Span)
            .Should().BeTrue("the signer owns the key once it is lent, so the source must not dispose it");
    }

    [Fact]
    public async Task A_second_read_reports_the_same_key()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.ReadAsync(ct);
        var second = await sut.ReadAsync(ct);

        second.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus
            .Should().Equal(first.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus,
                "minting a fresh key on a later read would invalidate every token already issued");
    }

    [Fact]
    public async Task A_second_read_leaves_the_signer_claimable()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;
        var set = await sut.ReadAsync(ct);
        await sut.ReadAsync(ct);

        using var signer = await sut.CreateSignerAsync(set.SigningKey.Id, ct);
        var signature = await signer.SignAsync("payload"u8.ToArray(), ct);

        SigningAlgorithms.Verify(
                SigningAlgorithm.RS256, set.SigningKey.PublicKey, "payload"u8, signature.Span)
            .Should().BeTrue("the memoized key set and the pending private key must stay in step");
    }

    [Fact]
    public async Task Concurrent_reads_report_one_key_and_leave_one_claimable_signer()
    {
        using var sut = BuildEphemeral();
        var ct = TestContext.Current.CancellationToken;

        var sets = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(_ => Task.Run(async () => await sut.ReadAsync(ct), ct)));

        var moduli = sets
            .Select(set => Convert.ToHexString(set.SigningKey.PublicKey.RsaPublicParameters!.Value.Modulus!))
            .Distinct();
        moduli.Should().ContainSingle("concurrent reads must not each mint their own key");

        using var signer = await sut.CreateSignerAsync(sets[0].SigningKey.Id, ct);
        var signature = await signer.SignAsync("payload"u8.ToArray(), ct);
        SigningAlgorithms.Verify(
                SigningAlgorithm.RS256, sets[0].SigningKey.PublicKey, "payload"u8, signature.Span)
            .Should().BeTrue();
    }

    // ── Fail-closed file checks ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Directory_with_too_permissive_mode_fails_closed()
    {
        using var sut = BuildPersisted(new InMemorySigningKeyFileSystem { DirectoryTooPermissive = true });

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*directory_too_permissive*");
    }

    [Fact]
    public async Task Key_file_with_too_permissive_permissions_fails_closed()
    {
        var fs = new InMemorySigningKeyFileSystem { FileTooPermissive = true };
        fs.SeedFile(Path.Join(PersistDirectory, KeyFileName), "dummy content");
        using var sut = BuildPersisted(fs);

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*file_too_permissive*");
    }

    [Fact]
    public async Task Key_file_reached_through_a_symlink_fails_closed()
    {
        var fs = new InMemorySigningKeyFileSystem { FileIsSymlink = true };
        fs.SeedFile(Path.Join(PersistDirectory, KeyFileName), "dummy content");
        using var sut = BuildPersisted(fs);

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*symlink_detected*");
    }

    [Fact]
    public async Task Corrupt_key_file_throws()
    {
        var fs = new InMemorySigningKeyFileSystem();
        fs.SeedFile(Path.Join(PersistDirectory, KeyFileName), "this is not a valid PEM");
        using var sut = BuildPersisted(fs);

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<Exception>("corrupt PEM must cause an exception");
    }

    [Fact]
    public async Task Write_failure_during_key_generation_rethrows()
    {
        using var sut = BuildPersisted(new ThrowOnWriteFileSystem());

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<IOException>("failure to write the key file must bubble out");
    }

    // ── Environment gate ─────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Production")]
    [InlineData("production")]
    [InlineData("PRODUCTION")]
    public async Task ReadAsync_throws_in_Production_regardless_of_AllowedEnvironments(string environmentName)
    {
        using var sut = BuildForEnvironment(environmentName, allowed: ["Production"]);

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>().WithMessage("*Production*");
    }

    [Theory]
    [InlineData("Staging")]
    [InlineData("IntegrationTest")]
    public async Task ReadAsync_throws_when_environment_not_in_AllowedEnvironments(string environmentName)
    {
        using var sut = BuildForEnvironment(environmentName, allowed: null);

        var act = () => sut.ReadAsync(TestContext.Current.CancellationToken).AsTask();

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>().WithMessage($"*{environmentName}*");
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("development")]
    [InlineData("DEVELOPMENT")]
    public async Task ReadAsync_succeeds_in_Development(string environmentName)
    {
        using var sut = BuildForEnvironment(environmentName, allowed: null);

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.Keys.Should().ContainSingle();
    }

    [Fact]
    public async Task ReadAsync_succeeds_when_environment_is_in_AllowedEnvironments()
    {
        using var sut = BuildForEnvironment("Staging", allowed: ["Development", "Staging"]);

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.Keys.Should().ContainSingle();
    }

    [Fact]
    public async Task ReadAsync_skips_the_gate_when_EnvironmentName_is_null()
    {
        using var sut = BuildForEnvironment(environmentName: null, allowed: null);

        var set = await sut.ReadAsync(TestContext.Current.CancellationToken);

        set.Keys.Should().ContainSingle("no host means no environment to gate on");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static DevelopmentSigningKeySource BuildEphemeral(IDevelopmentSigningKeyFileSystem? fileSystem = null)
        => new(
            Options.Create(new DevelopmentSigningKeyOptions()),
            fileSystem ?? new InMemorySigningKeyFileSystem());

    private static DevelopmentSigningKeySource BuildPersisted(IDevelopmentSigningKeyFileSystem fileSystem)
        => new(
            Options.Create(new DevelopmentSigningKeyOptions { PersistToDirectory = PersistDirectory }),
            fileSystem);

    private static DevelopmentSigningKeySource BuildForEnvironment(
        string? environmentName, IReadOnlyList<string>? allowed)
    {
        var options = new DevelopmentSigningKeyOptions { EnvironmentName = environmentName };

        if (allowed is not null)
            options.AllowedDevelopmentJwtSigningKeysEnvironments = allowed;

        return new DevelopmentSigningKeySource(Options.Create(options), new InMemorySigningKeyFileSystem());
    }

    private static RSA? PendingPrivateKeyOf(DevelopmentSigningKeySource source)
        => (RSA?)typeof(DevelopmentSigningKeySource)
            .GetField("_pendingPrivateKey", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(source);
}
