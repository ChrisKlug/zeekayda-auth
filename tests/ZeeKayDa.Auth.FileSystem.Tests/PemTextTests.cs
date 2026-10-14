using System.Buffers;
using System.Text;

namespace ZeeKayDa.Auth.FileSystem.Tests;

public sealed class PemTextTests
{
    private const string Pem = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n";

    [Fact]
    public void Decode_wipes_the_input_bytes()
    {
        var bytes = Encoding.UTF8.GetBytes(Pem);

        using var text = PemText.Decode(bytes, new RecordingPool());

        bytes.Should().OnlyContain(b => b == 0, "the file's bytes may hold a private key");
        text.Span.ToString().Should().Be(Pem);
    }

    [Fact]
    public void Dispose_wipes_the_buffer_before_returning_it_to_the_pool()
    {
        var pool = new RecordingPool();
        var text = PemText.Decode(Encoding.UTF8.GetBytes(Pem), pool);

        text.Dispose();

        pool.Returned.Should().ContainSingle().Which.Should().OnlyContain(c => c == '\0',
            "a pooled buffer is handed to the next renter as it is");
        pool.WasClearedWhenReturned.Should().ContainSingle().Which.Should().BeTrue();
    }

    [Fact]
    public void Dispose_twice_returns_the_buffer_once()
    {
        var pool = new RecordingPool();
        var text = PemText.Decode(Encoding.UTF8.GetBytes(Pem), pool);

        text.Dispose();
        text.Dispose();

        pool.Returned.Should().ContainSingle("returning a buffer twice would hand it to two renters");
    }

    /// <summary>An <see cref="ArrayPool{T}"/> that records each returned buffer and whether it was already wiped.</summary>
    private sealed class RecordingPool : ArrayPool<char>
    {
        public List<char[]> Returned { get; } = [];

        public List<bool> WasClearedWhenReturned { get; } = [];

        public override char[] Rent(int minimumLength) => new char[minimumLength];

        public override void Return(char[] array, bool clearArray = false)
        {
            WasClearedWhenReturned.Add(array.All(c => c == '\0'));
            Returned.Add(array);
        }
    }
}
