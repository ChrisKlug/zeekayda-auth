using System.Security.AccessControl;
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
        AssertWholeKey(path);
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
        var paths = await RaceToEnsureAsync(AssertWholeKey);

        paths.Should().AllBe(KeyPath);
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

        await RaceToEnsureAsync(path => UnixModeOf(path).Should().Be(OwnerOnly));
    }

    [Fact]
    public void Ensure_publishes_a_non_inherited_owner_only_acl_on_windows()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        SigningKeyFile.Ensure(KeyPath);

        AssertOwnerOnlyProtectedAcl(KeyPath);
    }

    [Fact]
    public async Task Ensure_publishes_a_non_inherited_owner_only_acl_on_windows_when_callers_race()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), RequiresWindowsReason);

        await RaceToEnsureAsync(AssertOwnerOnlyProtectedAcl);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// Calls <c>Ensure</c> from several threads released together, and returns what each was given.
    /// </summary>
    /// <param name="checkWhatThisCallerGot">
    /// Run inside each racing task, before it completes. The check has to happen there: a caller
    /// that returns while another is still writing the key must already be holding a whole one, and
    /// by the time every task has finished the writer has finished too, so a check afterwards would
    /// pass against an implementation that publishes the key before it is complete.
    /// </param>
    private async Task<string[]> RaceToEnsureAsync(Action<string> checkWhatThisCallerGot)
    {
        using var start = new ManualResetEventSlim();
        var callers = Enumerable.Range(0, Racers)
            .Select(_ => Task.Run(
                () =>
                {
                    start.Wait(Cancellation);
                    var path = SigningKeyFile.Ensure(KeyPath);
                    checkWhatThisCallerGot(path);
                    return path;
                },
                Cancellation))
            .ToArray();

        start.Set();

        return await Task.WhenAll(callers);
    }

    private static void AssertWholeKey(string path)
    {
        using var certificate = X509Certificate2.CreateFromPemFile(path);
        certificate.HasPrivateKey.Should().BeTrue();
    }

    // The two helpers below carry their own OperatingSystem guard rather than relying on the
    // Assert.Skip* call at the top of each test: CA1416 cannot see that a skip aborts the test, so
    // a bare File.GetUnixFileMode/GetAccessControl call would fail the build. The unreachable
    // branch is inert — every caller is already skipped off-platform.

    private static UnixFileMode UnixModeOf(string path) =>
        OperatingSystem.IsWindows() ? UnixFileMode.None : File.GetUnixFileMode(path);

    private static void AssertOwnerOnlyProtectedAcl(string path)
    {
        if (!OperatingSystem.IsWindows())
            return;

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
    }
}
