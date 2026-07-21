namespace ZeeKayDa.Auth.FileSystem.Tests;

/// <summary>
/// Direct unit tests for <see cref="RegisteredSigningFile"/> — a shared type used differently by its
/// two callers (the PFX provider never registers <see cref="RegisteredSigningFile.AdditionalPaths"/>;
/// the PEM provider does, for its split cert/key file support), so both branches of
/// <see cref="RegisteredSigningFile.AllPaths"/> are covered here directly rather than relying on
/// either provider's own test suite to exercise both.
/// </summary>
public sealed class RegisteredSigningFileTests
{
    [Fact]
    public void AllPaths_returns_only_Id_when_there_are_no_additional_paths()
    {
        var file = new RegisteredSigningFile("/etc/zeekayda/signing.pfx");

        file.AllPaths.Should().Equal("/etc/zeekayda/signing.pfx");
    }

    [Fact]
    public void AllPaths_returns_Id_followed_by_additional_paths()
    {
        var file = new RegisteredSigningFile("/etc/zeekayda/signing.pem", ["/etc/zeekayda/signing.key"]);

        file.AllPaths.Should().Equal("/etc/zeekayda/signing.pem", "/etc/zeekayda/signing.key");
    }

    [Fact]
    public void Constructor_throws_when_id_is_null_or_whitespace()
    {
        var act = () => new RegisteredSigningFile("   ");

        act.Should().Throw<ArgumentException>();
    }
}
