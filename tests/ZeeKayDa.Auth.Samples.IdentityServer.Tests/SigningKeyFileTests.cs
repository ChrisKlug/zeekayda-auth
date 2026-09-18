using System.Security.Cryptography.X509Certificates;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Tests;

/// <summary>
/// The sample generates its signing key on first run, and more than one host can be starting at
/// the same time — the test suite alone runs two sample assemblies in parallel, each hosting the
/// sample. These prove the key is published whole and owner-only however many hosts race for it.
/// </summary>
public sealed class SigningKeyFileTests : IDisposable
{
    // Enough to lose the race reliably, few enough that generating a key on each does not
    // starve the sample's own smoke tests of CPU while they run alongside these.
    private const int Racers = 8;

    private const string RequiresUnixReason = "Unix file modes do not exist on Windows.";
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _directory = Path.Join(Path.GetTempPath(), Path.GetRandomFileName());

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private string KeyPath => Path.Join(_directory, "signing.pem");

    [Fact]
    public void Ensure_generates_a_usable_key_on_first_run()
    {
        var path = SigningKeyFile.Ensure(KeyPath);

        path.Should().Be(KeyPath);
        using var certificate = X509Certificate2.CreateFromPemFile(path);
        certificate.HasPrivateKey.Should().BeTrue();
    }

    [Fact]
    public void Ensure_keeps_the_key_it_already_generated()
    {
        SigningKeyFile.Ensure(KeyPath);
        var generated = File.ReadAllText(KeyPath);

        SigningKeyFile.Ensure(KeyPath);

        File.ReadAllText(KeyPath).Should().Be(generated);
    }

    [Fact]
    public async Task Ensure_gives_every_racing_caller_the_same_whole_key()
    {
        var paths = await RaceToEnsureAsync();

        paths.Should().AllBe(KeyPath);
        using var certificate = X509Certificate2.CreateFromPemFile(KeyPath);
        certificate.HasPrivateKey.Should().BeTrue();
        Directory.GetFiles(_directory).Should().ContainSingle().Which.Should().Be(KeyPath);
    }

    [Fact]
    public void Ensure_publishes_an_owner_only_key_on_unix()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        SigningKeyFile.Ensure(KeyPath);

        UnixModeOf(KeyPath).Should().Be(OwnerOnly);
    }

    [Fact]
    public async Task Ensure_publishes_an_owner_only_key_on_unix_when_callers_race()
    {
        Assert.SkipWhen(OperatingSystem.IsWindows(), RequiresUnixReason);

        await RaceToEnsureAsync();

        UnixModeOf(KeyPath).Should().Be(OwnerOnly);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // The guard is repeated here rather than left to the Assert.SkipWhen at the top of each test:
    // CA1416 cannot see that a skip aborts the test, so a bare call would fail the build.
    private static UnixFileMode UnixModeOf(string path) =>
        OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(path);

    /// <summary>Calls <c>Ensure</c> from several threads released together, and returns what each got.</summary>
    private async Task<string[]> RaceToEnsureAsync()
    {
        using var start = new ManualResetEventSlim();
        var callers = Enumerable.Range(0, Racers)
            .Select(_ => Task.Run(
                () =>
                {
                    start.Wait(Cancellation);
                    return SigningKeyFile.Ensure(KeyPath);
                },
                Cancellation))
            .ToArray();

        start.Set();

        return await Task.WhenAll(callers);
    }
}
