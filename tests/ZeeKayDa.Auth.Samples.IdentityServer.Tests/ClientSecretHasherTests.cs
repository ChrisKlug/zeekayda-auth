using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

namespace ZeeKayDa.Auth.Samples.IdentityServer.Tests;

/// <summary>
/// The sample hashers bound what they accept: a sample is what integrators copy, so each one
/// demonstrates refusing a weak, malformed or ruinously expensive stored secret.
/// </summary>
public sealed class ClientSecretHasherTests
{
    private const string BCryptHash = "$2a$12$kCkuJxtdpoxHqdx13S57Q.ziYD3bDcjM8PCfxTyp.TKoKDDxkbYFi";
    private const string Argon2Hash = "$argon2id$v=19$m=65536,t=3,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g";

    [Fact]
    public void BCrypt_refuses_to_create_a_secret_longer_than_the_72_bytes_bcrypt_reads()
    {
        var act = () => new BCryptClientSecretHasher().Create(new string('x', 73));

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void BCrypt_does_not_verify_a_presented_secret_longer_than_72_bytes()
    {
        // Every secret sharing the first 72 bytes would otherwise match the same hash.
        var hasher = new BCryptClientSecretHasher();
        var stored = new ClientSecret(BCryptHash);

        hasher.Verify(stored, "bcrypt-client-secret" + new string('x', 60)).Should().BeFalse();
        hasher.Verify(stored, "bcrypt-client-secret").Should().BeTrue();
    }

    [Theory]
    [InlineData("$2a$04$kCkuJxtdpoxHqdx13S57Q.ziYD3bDcjM8PCfxTyp.TKoKDDxkbYFi", "sample.bcrypt.cost_out_of_range")]
    [InlineData("$2a$31$kCkuJxtdpoxHqdx13S57Q.ziYD3bDcjM8PCfxTyp.TKoKDDxkbYFi", "sample.bcrypt.cost_out_of_range")]
    [InlineData("$2a$12$tooshort", "sample.bcrypt.malformed")]
    [InlineData("$2a$12$kCkuJxtdpoxHqdx13S57Q.ziYD3bDcjM8PCfxTyp.TKoKDDxkbYFi ", "sample.bcrypt.malformed")]
    public void BCrypt_refuses_a_stored_secret_that_is_malformed_or_outside_its_cost_bounds(string value, string code)
    {
        var hasher = new BCryptClientSecretHasher();

        hasher.ValidateStoredSecret(new ClientSecret(value)).Should().ContainSingle().Which.Code.Should().Be(code);
        hasher.Verify(new ClientSecret(value), "bcrypt-client-secret").Should().BeFalse();
    }

    [Theory]
    [InlineData("$argon2id$v=19$m=1024,t=3,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=4194304,t=3,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=65536,t=100,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=16$m=65536,t=3,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$t=3,m=65536,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=786432,t=1,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=19456,t=1,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=262144,t=10,p=1$gvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=1$gvJfb2maq7pkagaITSD2kQgvJfb2maq7pkagaITSD2kQ$qAaUvaI9kD5x5sqbxTG8U5jMh4YoRYmS8jjmOr3bX3g")]
    public void Argon2_refuses_a_stored_secret_that_is_malformed_or_outside_its_cost_bounds(string value)
    {
        var hasher = new Argon2ClientSecretHasher();

        hasher.ValidateStoredSecret(new ClientSecret(value)).Should().ContainSingle()
            .Which.Code.Should().Be("sample.argon2.unacceptable");
        hasher.Verify(new ClientSecret(value), "argon2-client-secret").Should().BeFalse();
    }

    [Fact]
    public void Argon2_accepts_and_verifies_the_sample_client_s_secret()
    {
        var hasher = new Argon2ClientSecretHasher();

        hasher.ValidateStoredSecret(new ClientSecret(Argon2Hash)).Should().BeEmpty();
        hasher.Verify(new ClientSecret(Argon2Hash), "argon2-client-secret").Should().BeTrue();
    }

    [Fact]
    public void Pbkdf2Sha512_refuses_a_stored_secret_with_a_version_field()
    {
        var hasher = new Pbkdf2Sha512ClientSecretHasher();
        var versioned = new PhcString(
            "pbkdf2-sha512", new byte[16], new byte[64], [new("i", "210000")], version: 19).ToString();

        hasher.ValidateStoredSecret(new ClientSecret(versioned)).Should().ContainSingle()
            .Which.Code.Should().Be("sample.pbkdf2_sha512.malformed");
    }

    [Fact]
    public void Pbkdf2Sha512_refuses_a_stored_secret_with_a_salt_of_the_wrong_length()
    {
        var hasher = new Pbkdf2Sha512ClientSecretHasher();
        var shortSalt = new PhcString("pbkdf2-sha512", new byte[8], new byte[64], [new("i", "210000")]).ToString();

        hasher.ValidateStoredSecret(new ClientSecret(shortSalt)).Should().ContainSingle()
            .Which.Code.Should().Be("sample.pbkdf2_sha512.malformed");
    }
}
