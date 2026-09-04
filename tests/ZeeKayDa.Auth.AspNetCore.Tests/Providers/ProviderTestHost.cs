using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Providers;

/// <summary>
/// What the external round-trip tests share: a real OAuth provider ("acme") whose token endpoint
/// is faked so the callback completes in-process, a hand-written handler outside the remote base
/// class, and the host's own pages — a login page that starts the round trip, a collect-more page
/// that reads a parked principal, and a probe reporting the session.
/// </summary>
internal static class ProviderTestHost
{
    public const string RegisteredRedirect = "https://test.example.com/callback";
    public const string LoginPath = "/account/login";
    public const string CollectMorePath = "/collect-more";
    public const string UpstreamSubject = "upstream-42";
    public const string HandWrittenIssuer = "https://hand.example.net";
    public const string HandWrittenSubject = "hand-7";

    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// <summary>A working OAuth provider: every endpoint set, the token exchange faked, a subject claim added.</summary>
    public static void ConfigureAcme(OAuthOptions options) => ConfigureOAuth(options, new FakeTokenEndpoint(succeed: true));

    /// <summary>An OAuth provider whose token endpoint is down.</summary>
    public static void ConfigureBroken(OAuthOptions options) => ConfigureOAuth(options, new FakeTokenEndpoint(succeed: false));

    private static void ConfigureOAuth(OAuthOptions options, HttpMessageHandler backchannel)
    {
        options.ClientId = "acme-client";
        options.ClientSecret = "acme-secret";
        options.AuthorizationEndpoint = "https://acme.example.net/authorize";
        options.TokenEndpoint = "https://acme.example.net/token";
        options.BackchannelHttpHandler = backchannel;

        // The generic OAuth handler creates an empty identity; a real provider package maps the
        // user-information response into claims here, stamping the handler's claims issuer —
        // the options value when set, else the scheme name.
        options.Events.OnCreatingTicket = context =>
        {
            var issuer = context.Options.ClaimsIssuer ?? context.Scheme.Name;
            context.Identity!.AddClaim(new Claim("sub", UpstreamSubject, ClaimValueTypes.String, issuer));
            context.Identity.AddClaim(new Claim("name", "Upstream User", ClaimValueTypes.String, issuer));
            return Task.CompletedTask;
        };
    }

    /// <summary>
    /// Registers the hand-written handler the way a raw <see cref="IAuthenticationHandler"/> is
    /// registered: straight into the scheme map, since the typed <c>AddScheme</c> is reserved for
    /// handlers deriving from the base class.
    /// </summary>
    public static void AddHandWritten(
        AuthenticationBuilder auth,
        Action<HandWrittenOptions>? configure = null,
        bool registerHandler = true)
    {
        auth.Services.Configure<AuthenticationOptions>(options => options.AddScheme<HandWrittenHandler>("hand", "Hand"));
        if (registerHandler)
            auth.Services.AddTransient<HandWrittenHandler>();
        auth.Services.Configure("hand", configure ?? (_ => { }));
    }

    public static HttpClient NewClient(TestWebAppFactory factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://test.example.com"),
        AllowAutoRedirect = false,
        HandleCookies = true,
    });

    /// <summary>The host's pages.</summary>
    public static void MapHostPages(IEndpointRouteBuilder endpoints)
    {
        // The login page: a provider button posts the provider's id, the credential form posts a
        // subject. Both end in a terminal call.
        endpoints.MapPost(LoginPath, async (HttpContext context, ILoginInteraction login) =>
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);

            if (form["provider"].FirstOrDefault() is { Length: > 0 } provider)
            {
                await login.ChallengeAsync(provider);
                return;
            }

            var subject = form["sub"].FirstOrDefault() ?? "user-1";
            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", subject)], "test")),
                AuthenticationMethods.Password);
        });

        endpoints.MapPost("/account/login/cancel", (ILoginInteraction login) => login.DenyAsync());

        // The collect-more page: reports the parked principal, and on post maps it onto a local
        // account and signs that in.
        endpoints.MapGet(CollectMorePath, async (ILoginInteraction login) =>
        {
            var pending = await login.GetPendingPrincipalAsync();

            return pending is null
                ? Results.NotFound()
                : Results.Ok(new
                {
                    sub = pending.Principal.FindFirstValue("sub"),
                    provider = pending.Provider.Id,
                    reservedClaims = pending.Principal.Claims.Count(claim => claim.Type.StartsWith("zkd:", StringComparison.OrdinalIgnoreCase)),
                });
        });

        endpoints.MapPost(CollectMorePath, async (ILoginInteraction login) =>
        {
            var pending = await login.GetPendingPrincipalAsync()
                ?? throw new InvalidOperationException("Nothing is parked for this page.");

            await login.SignInAsync(
                new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim("sub", "mapped-" + pending.Principal.FindFirstValue("sub"))], "test")),
                AuthenticationMethods.Password);
        });

        // What the invariant forbids and the framework refuses: a host page signing into the
        // framework's external scheme by name.
        endpoints.MapGet("/test/sign-in-external", (HttpContext context) => context.SignInAsync(
            ZeeKayDaCookies.External,
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "forged")], "host"))));

        endpoints.MapGet("/test/session", async (HttpContext context) =>
        {
            var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session);

            return result.Succeeded
                ? Results.Ok(new
                {
                    sid = result.Principal!.FindFirstValue(SsoSessionClaimTypes.SessionId),
                    sub = result.Principal.FindFirstValue("sub"),
                    name = result.Principal.FindFirstValue("name"),
                    amr = result.Principal.FindAll(SsoSessionClaimTypes.Amr).Select(claim => claim.Value).ToArray(),
                })
                : Results.NotFound();
        });
    }

    public static string AuthorizeUrl(string? state = null)
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = "test-client",
            ["redirect_uri"] = RegisteredRedirect,
            ["response_type"] = "code",
            ["scope"] = "openid",
            ["nonce"] = "n-0S6_WzA2Mj",
            ["code_challenge"] = Challenge,
            ["code_challenge_method"] = "S256",
        };

        if (state is not null)
            query["state"] = state;

        return QueryHelpers.AddQueryString("/connect/authorize", query);
    }

    /// <summary>The interaction identifier the framework put on a redirect to a host page.</summary>
    public static string InteractionIdFrom(HttpResponseMessage response) =>
        RedirectQueryOf(response)[InteractionHandoff.InteractionIdParameter]!;

    /// <summary>The parsed query of a redirect.</summary>
    public static Dictionary<string, StringValues> RedirectQueryOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!.OriginalString;
        return QueryHelpers.ParseQuery(location[location.IndexOf('?')..]);
    }

    /// <summary>Where a redirect points — scheme, authority and path, with the query stripped.</summary>
    public static string DestinationOf(HttpResponseMessage response) =>
        new Uri(new Uri("https://test.example.com"), response.Headers.Location!).GetLeftPart(UriPartial.Path);

    public static string WithInteractionId(string path, string interactionId) =>
        QueryHelpers.AddQueryString(path, InteractionHandoff.InteractionIdParameter, interactionId);

    public static FormUrlEncodedContent Form(params (string Key, string Value)[] fields) =>
        new(fields.Select(field => KeyValuePair.Create(field.Key, field.Value)));

    /// <summary>
    /// The token endpoint the OAuth handler exchanges its code at, answered in-process: a bearer
    /// token, or a 500 when the provider is down.
    /// </summary>
    private sealed class FakeTokenEndpoint(bool succeed) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(succeed
                ? new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        """{"access_token":"acme-token","token_type":"Bearer","expires_in":3600}""",
                        Encoding.UTF8,
                        "application/json"),
                }
                : new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("upstream outage", Encoding.UTF8, "text/plain"),
                });
    }

    /// <summary>How a hand-written handler misbehaves, one way per test.</summary>
    public sealed class HandWrittenOptions : AuthenticationSchemeOptions
    {
        /// <summary>Sign in with fresh properties instead of the ones the challenge carried.</summary>
        public bool DropProperties { get; set; }

        /// <summary>Create the subject claim without an issuer.</summary>
        public bool SubjectWithoutIssuer { get; set; }

        /// <summary>Return <see langword="false"/> from the callback.</summary>
        public bool DeclineCallback { get; set; }

        /// <summary>Stamp another scheme's name where a remote handler stamps its own.</summary>
        public bool StampAnotherScheme { get; set; }
    }

    /// <summary>
    /// A provider handler outside the remote base class, written to the contract the design
    /// states: implements <see cref="IAuthenticationRequestHandler"/>, carries the properties it
    /// was challenged with through a protected <c>state</c> parameter, and finishes with a sign-in
    /// to the framework's external scheme followed by a redirect to the properties' return URL.
    /// </summary>
    public sealed class HandWrittenHandler(
        IOptionsMonitor<HandWrittenOptions> options,
        IDataProtectionProvider dataProtection) : IAuthenticationRequestHandler
    {
        private readonly PropertiesDataFormat _state = new(dataProtection.CreateProtector("hand-written-state"));
        private AuthenticationScheme _scheme = null!;
        private HttpContext _context = null!;

        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            _scheme = scheme;
            _context = context;
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync() => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(AuthenticationProperties? properties)
        {
            _context.Response.Redirect(
                HandWrittenIssuer + "/authorize?state=" + Uri.EscapeDataString(_state.Protect(properties ?? new AuthenticationProperties())));
            return Task.CompletedTask;
        }

        public Task ForbidAsync(AuthenticationProperties? properties) => Task.CompletedTask;

        public async Task<bool> HandleRequestAsync()
        {
            var settings = options.Get(_scheme.Name);
            if (settings.DeclineCallback)
                return false;

            var properties = _state.Unprotect(_context.Request.Query["state"])
                ?? throw new InvalidOperationException("The state did not unprotect.");

            var issuer = settings.SubjectWithoutIssuer ? ClaimsIdentity.DefaultIssuer : HandWrittenIssuer;
            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", HandWrittenSubject, ClaimValueTypes.String, issuer)], _scheme.Name));

            if (settings.StampAnotherScheme)
                properties.Items[".AuthScheme"] = "someone-else";

            await _context.SignInAsync(
                ZeeKayDaCookies.External,
                principal,
                settings.DropProperties ? new AuthenticationProperties() : properties);

            _context.Response.Redirect(properties.RedirectUri ?? "/");
            return true;
        }
    }
}
