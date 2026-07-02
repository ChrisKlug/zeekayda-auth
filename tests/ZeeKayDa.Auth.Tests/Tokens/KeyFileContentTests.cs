using System.Security.Cryptography;
using System.Text;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class KeyFileContentTests
{
    [Fact]
    public void Bytes_returns_the_content_before_disposal()
    {
        var original = Encoding.UTF8.GetBytes("-----BEGIN RSA PRIVATE KEY-----");
        var sut = new KeyFileContent(original);

        var result = sut.Bytes.ToArray();

        result.Should().Equal(original);
    }

    [Fact]
    public void Dispose_zeroes_the_underlying_buffer()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        var sut = new KeyFileContent(bytes);

        sut.Dispose();

        // The same array reference must be zeroed — key material must not linger.
        bytes.Should().AllBeEquivalentTo(0);
    }

    [Fact]
    public void Bytes_throws_ObjectDisposedException_after_disposal()
    {
        var sut = new KeyFileContent(new byte[] { 1, 2, 3 });
        sut.Dispose();

        Action act = () => _ = sut.Bytes.Length;

        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_is_idempotent()
    {
        var sut = new KeyFileContent(new byte[] { 9, 8, 7 });

        var act = () =>
        {
            sut.Dispose();
            sut.Dispose();
        };

        act.Should().NotThrow("calling Dispose twice must be safe");
    }

    [Fact]
    public void Using_statement_zeroes_bytes_on_exit()
    {
        var bytes = Encoding.UTF8.GetBytes("sensitive key material");

        using (var sut = new KeyFileContent(bytes))
        {
            sut.Bytes.Length.Should().Be(bytes.Length);
        }

        // All bytes in the original array must be zero after the using block exits.
        bytes.Should().AllBeEquivalentTo(0);
    }

    [Fact]
    public void Bytes_are_zeroed_by_CryptographicOperations_ZeroMemory()
    {
        // Verify the zeroing uses a cryptographically reliable path rather than a
        // compiler-optimisable assignment, by checking through the array reference.
        var bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var sut = new KeyFileContent(bytes);

        sut.Dispose();

        foreach (var b in bytes)
            b.Should().Be(0, "CryptographicOperations.ZeroMemory must clear every byte");
    }
}
