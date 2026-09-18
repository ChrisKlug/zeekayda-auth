using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

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
    private const string RequiresWindowsReason = "ACLs only exist on Windows.";
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly string _directory = Path.Join(Path.GetTempPath(), Path.GetRandomFileName());

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private string KeyPath => Path.Join(_directory, "signing.pem");

    [Fact]
    public void Ensure_generates_a_usable_key_on_first_run()
    {
        var path = SigningKeyFile.Ensure(KeyPath);

        path.Should().Be(KeyPath);
        ObserveWholeKey(path).Should().NotBeEmpty();
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
        var keys = await RaceToEnsureAsync(ObserveWholeKey);

        keys.Should().AllBe(keys[0], "every racing host has to end up signing with one key");
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

        var modes = await RaceToEnsureAsync(UnixModeOf);

        modes.Should().AllSatisfy(mode => mode.Should().Be(OwnerOnly));
    }

    [Fact]
    public void Ensure_publishes_a_non_inherited_owner_only_acl_on_windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        SigningKeyFile.Ensure(KeyPath);

        ObserveOwnerOnlyProtectedAcl(KeyPath);
    }

    [Fact]
    public async Task Ensure_publishes_a_non_inherited_owner_only_acl_on_windows_when_callers_race()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        await RaceToEnsureAsync(ObserveOwnerOnlyProtectedAcl);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// Calls <c>Ensure</c> from several threads released together, and returns what each was given.
    /// </summary>
    /// <param name="observeWhatThisCallerGot">
    /// Run inside each racing task, before it completes, and its return value is what the caller
    /// saw. Both halves matter. The observation has to happen there, because by the time every task
    /// has finished the writer has finished too, so a check afterwards would pass against an
    /// implementation that publishes the key before it is complete. And it has to be returned
    /// rather than only asserted, so the callers can be compared against each other — a caller
    /// holding a whole key proves nothing if it is not the same key its neighbour is holding.
    /// </param>
    private async Task<T[]> RaceToEnsureAsync<T>(Func<string, T> observeWhatThisCallerGot)
    {
        using var start = new ManualResetEventSlim();
        var callers = Enumerable.Range(0, Racers)
            .Select(_ => Task.Run(
                () =>
                {
                    start.Wait(Cancellation);
                    var path = SigningKeyFile.Ensure(KeyPath);

                    return observeWhatThisCallerGot(path);
                },
                Cancellation))
            .ToArray();

        start.Set();

        return await Task.WhenAll(callers);
    }

    /// <summary>
    /// Reads the key this caller was handed, proves both halves of it are there, and returns it
    /// verbatim so it can be compared with what the other callers were handed. One read: a second
    /// one could see a different file and would prove nothing about what this caller got.
    /// </summary>
    private string ObserveWholeKey(string path)
    {
        path.Should().Be(KeyPath);

        var pem = File.ReadAllText(path);
        using var certificate = X509Certificate2.CreateFromPem(pem);
        certificate.Subject.Should().Be("CN=ZeeKayDa sample signing key");
        using var privateKey = RSA.Create();
        privateKey.ImportFromPem(pem);

        return pem;
    }

    // The two helpers below carry their own OperatingSystem guard rather than relying on the
    // Assert.Skip* call at the top of each test: CA1416 cannot see that a skip aborts the test, so
    // a bare File.GetUnixFileMode/GetAccessControl call would fail the build. The unreachable
    // branch is inert — every caller is already skipped off-platform.

    private static UnixFileMode UnixModeOf(string path) =>
        OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(path);

    private static string ObserveOwnerOnlyProtectedAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
            return path;

        var security = new FileInfo(path).GetAccessControl();

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

        return path;
    }
}
