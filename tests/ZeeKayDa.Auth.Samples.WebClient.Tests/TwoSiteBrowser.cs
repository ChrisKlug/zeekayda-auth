using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;

namespace ZeeKayDa.Auth.Samples.WebClient.Tests;

/// <summary>
/// A browser for two in-process sites: each request goes to the test server for its origin, one
/// cookie jar serves both, and redirects are followed hop by hop so every URL visited can be
/// inspected afterwards.
/// </summary>
internal sealed partial class TwoSiteBrowser : IDisposable
{
    private const int MaxRedirects = 20;

    private readonly HttpClient _client;

    public TwoSiteBrowser(IReadOnlyDictionary<Uri, HttpMessageHandler> sites) =>
        _client = new HttpClient(new CookieContainerHandler(new CookieContainer())
        {
            InnerHandler = new OriginRouter(sites),
        });

    /// <summary>Every URL requested, in order, redirects included.</summary>
    public List<Uri> Visited { get; } = [];

    /// <summary>Loads a URL and follows its redirects; returns the page it ends on.</summary>
    public async Task<Page> GetAsync(Uri url, CancellationToken cancellationToken) =>
        await FollowAsync(new HttpRequestMessage(HttpMethod.Get, url), cancellationToken);

    /// <summary>
    /// Submits the page's form the way a browser would — with its antiforgery token, to its action
    /// or back to the page's own URL — and follows the redirects that answer it.
    /// </summary>
    public async Task<Page> SubmitAsync(Page page, Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        fields["__RequestVerificationToken"] = AntiforgeryToken().Match(page.Html).Groups[1].Value;
        var action = WebUtility.HtmlDecode(FormAction().Match(page.Html).Groups["action"].Value);
        var target = action.Length == 0 ? page.Url : new Uri(page.Url, action);

        return await FollowAsync(
            new HttpRequestMessage(HttpMethod.Post, target) { Content = new FormUrlEncodedContent(fields) },
            cancellationToken);
    }

    public void Dispose() => _client.Dispose();

    private async Task<Page> FollowAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        for (var hop = 0; hop <= MaxRedirects; hop++)
        {
            var url = request.RequestUri!;
            Visited.Add(url);

            var (status, location, body) = await SendAsync(request, cancellationToken);
            if (status is HttpStatusCode.Redirect or HttpStatusCode.SeeOther)
            {
                request = new HttpRequestMessage(HttpMethod.Get, new Uri(url, location!));
                continue;
            }

            // A failure's body is the developer exception page; it says why, not only that.
            status.Should().Be(HttpStatusCode.OK, because: $"{url} answered: {body[..Math.Min(body.Length, 3000)]}");
            return new Page(url, body);
        }

        throw new InvalidOperationException($"More than {MaxRedirects} redirects.");
    }

    private async Task<(HttpStatusCode Status, Uri? Location, string Body)> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using (request)
        using (var response = await _client.SendAsync(request, cancellationToken))
        {
            return (response.StatusCode, response.Headers.Location, await response.Content.ReadAsStringAsync(cancellationToken));
        }
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();

    // HTML attribute names are case-insensitive, and a value may be double-, single- or unquoted.
    [GeneratedRegex("""<form\b[^>]*\saction\s*=\s*(?:"(?<action>[^"]*)"|'(?<action>[^']*)'|(?<action>[^\s>"']+))""", RegexOptions.IgnoreCase)]
    private static partial Regex FormAction();

    private sealed class OriginRouter(IReadOnlyDictionary<Uri, HttpMessageHandler> sites) : HttpMessageHandler
    {
        private readonly Dictionary<string, HttpMessageInvoker> _invokers = sites.ToDictionary(
            site => site.Key.GetLeftPart(UriPartial.Authority),
            site => new HttpMessageInvoker(site.Value));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            _invokers.TryGetValue(request.RequestUri!.GetLeftPart(UriPartial.Authority), out var invoker)
                ? invoker.SendAsync(request, cancellationToken)
                : throw new InvalidOperationException($"No site is hosted at {request.RequestUri}.");

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (var invoker in _invokers.Values)
                    invoker.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

/// <summary>A page the browser ended on.</summary>
internal sealed record Page(Uri Url, string Html);
