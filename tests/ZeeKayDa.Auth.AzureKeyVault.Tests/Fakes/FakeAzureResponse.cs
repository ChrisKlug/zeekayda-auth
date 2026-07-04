using Azure;
using Azure.Core;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;

/// <summary>
/// A minimal <see cref="Response"/> implementation so tests can construct a
/// <see cref="RequestFailedException"/> that carries response headers (e.g. <c>Retry-After</c>)
/// without any real HTTP call. <see cref="Response.Headers"/>'s default implementation
/// (<c>new ResponseHeaders(this)</c>) delegates to <see cref="TryGetHeader"/>, so implementing
/// only the base class's abstract members is sufficient to make header lookups work end to end.
/// </summary>
internal sealed class FakeAzureResponse : Response
{
    private readonly IReadOnlyDictionary<string, string> _headers;

    public FakeAzureResponse(int status, IReadOnlyDictionary<string, string>? headers = null)
    {
        Status = status;
        _headers = headers ?? new Dictionary<string, string>();
    }

    public override int Status { get; }

    public override string ReasonPhrase => string.Empty;

    public override Stream? ContentStream { get; set; }

    public override string ClientRequestId { get; set; } = string.Empty;

    public override void Dispose() { }

    protected override bool TryGetHeader(string name, out string value)
    {
        if (_headers.TryGetValue(name, out var found))
        {
            value = found;
            return true;
        }

        value = null!;
        return false;
    }

    protected override bool TryGetHeaderValues(string name, out IEnumerable<string> values)
    {
        if (_headers.TryGetValue(name, out var found))
        {
            values = [found];
            return true;
        }

        values = [];
        return false;
    }

    protected override bool ContainsHeader(string name) => _headers.ContainsKey(name);

    protected override IEnumerable<HttpHeader> EnumerateHeaders() =>
        _headers.Select(kv => new HttpHeader(kv.Key, kv.Value));
}
