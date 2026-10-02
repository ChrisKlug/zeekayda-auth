using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class PhcStringTests
{
    private static readonly byte[] Salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    private static readonly byte[] Hash = [0xfb, 0xff, 0x00, 0x10];

    // ── Formatting ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Formats_id_salt_and_hash_as_unpadded_standard_base64()
    {
        new PhcString("pbkdf2-sha256", Salt, Hash).ToString()
            .Should().Be("$pbkdf2-sha256$AAECAwQFBgcICQoLDA0ODw$+/8AEA");
    }

    [Fact]
    public void Formats_version_and_parameters_in_order()
    {
        var phc = new PhcString(
            "argon2id", Salt, Hash,
            [new("m", "65536"), new("t", "3"), new("p", "4")],
            version: 19);

        phc.ToString().Should().Be("$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$+/8AEA");
    }

    [Fact]
    public void Copies_salt_and_hash_so_the_caller_cannot_edit_them_afterwards()
    {
        var salt = (byte[])Salt.Clone();

        var phc = new PhcString("id", salt, Hash);
        salt[0] = 0xff;

        phc.Salt.ToArray().Should().Equal(Salt);
    }

    [Fact]
    public void Salt_and_hash_cannot_be_changed_through_the_memory_they_return()
    {
        var phc = new PhcString("id", Salt, Hash);

        System.Runtime.InteropServices.MemoryMarshal.TryGetArray(phc.Salt, out var salt).Should().BeTrue();
        System.Runtime.InteropServices.MemoryMarshal.TryGetArray(phc.Hash, out var hash).Should().BeTrue();
        salt.Array![0] ^= 0xff;
        hash.Array![0] ^= 0xff;

        phc.Salt.ToArray().Should().Equal(Salt);
        phc.Hash.ToArray().Should().Equal(Hash);
        phc.ToString().Should().Be("$id$AAECAwQFBgcICQoLDA0ODw$+/8AEA");
    }

    // ── Constructor refusals ─────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("Upper")]
    [InlineData("has$dollar")]
    [InlineData("has_underscore")]
    [InlineData("abcdefghijklmnopqrstuvwxyz1234567")]
    public void Refuses_an_id_outside_the_format(string id)
    {
        var act = () => new PhcString(id, Salt, Hash);

        act.Should().Throw<ArgumentException>().WithParameterName("id");
    }

    [Fact]
    public void Refuses_an_empty_salt_or_hash()
    {
        var noSalt = () => new PhcString("id", [], Hash);
        var noHash = () => new PhcString("id", Salt, []);

        noSalt.Should().Throw<ArgumentException>().WithParameterName("salt");
        noHash.Should().Throw<ArgumentException>().WithParameterName("hash");
    }

    [Fact]
    public void Refuses_a_negative_version()
    {
        var act = () => new PhcString("id", Salt, Hash, version: -1);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData("i", "1$2")]
    [InlineData("i", "1,2")]
    [InlineData("i", "1=2")]
    [InlineData("i", "")]
    [InlineData("I", "1")]
    [InlineData("v", "1")]
    [InlineData("", "1")]
    public void Refuses_a_parameter_that_could_not_round_trip(string name, string value)
    {
        var act = () => new PhcString("id", Salt, Hash, [new(name, value)]);

        act.Should().Throw<ArgumentException>().WithParameterName("parameters");
    }

    [Fact]
    public void Refuses_a_repeated_parameter_name()
    {
        var act = () => new PhcString("id", Salt, Hash, [new("i", "1"), new("i", "2")]);

        act.Should().Throw<ArgumentException>().WithParameterName("parameters");
    }

    // ── Parsing ──────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("$pbkdf2-sha256$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=4$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$argon2id$v=19$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    public void A_parsed_string_formats_back_to_itself(string value)
    {
        PhcString.TryParse(value, out var phc).Should().BeTrue();

        phc!.ToString().Should().Be(value);
    }

    [Fact]
    public void Parses_every_part()
    {
        PhcString.TryParse("$argon2id$v=19$m=65536,t=3$AAECAwQFBgcICQoLDA0ODw$+/8AEA", out var phc)
            .Should().BeTrue();

        phc!.Id.Should().Be("argon2id");
        phc.Version.Should().Be(19);
        phc.Parameters.Should().Equal(
            new KeyValuePair<string, string>("m", "65536"),
            new KeyValuePair<string, string>("t", "3"));
        phc.Salt.ToArray().Should().Equal(Salt);
        phc.Hash.ToArray().Should().Equal(Hash);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("plaintext")]
    [InlineData("$")]
    [InlineData("$id")]
    [InlineData("$id$AAECAwQFBgcICQoLDA0ODw")]
    [InlineData("$id$AAECAwQFBgcICQoLDA0ODw$")]
    [InlineData("$id$$+/8AEA")]
    [InlineData("$ID$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$AAECAwQFBgcICQoLDA0ODw==$+/8AEA")]
    [InlineData("$id$AAECAwQFBgcICQoLDA0ODx$+/8AEA")]
    [InlineData("$id$AAECAwQFBgcICQoLDA0OD$+/8AEA")]
    [InlineData("$id$AAEC.wQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$i=1$v=19$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$v=19$i=1$x=2$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$i=1,i=2$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$i$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$i=$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$v=99999999999$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$id$v=+1$AAECAwQFBgcICQoLDA0ODw$+/8AEA")]
    [InlineData("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW")]
    public void TryParse_refuses_anything_that_is_not_a_well_formed_PHC_string(string? value)
    {
        PhcString.TryParse(value, out var phc).Should().BeFalse();
        phc.Should().BeNull();
    }
}
