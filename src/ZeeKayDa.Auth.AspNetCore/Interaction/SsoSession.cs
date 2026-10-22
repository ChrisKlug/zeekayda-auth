using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The claim types the framework mints into the SSO session cookie, in the reserved <c>zkd:</c>
/// namespace that is stripped from every host-supplied principal.
/// </summary>
internal static class SsoSessionClaimTypes
{
    /// <summary>The SSO session identifier. Stable from sign-in to sign-out.</summary>
    public const string SessionId = "zkd:sid";

    /// <summary>When the user last authenticated, as Unix seconds.</summary>
    public const string AuthTime = "zkd:auth_time";

    /// <summary>When this browser last signed the account in, as Unix seconds; the account's lifetime runs from it.</summary>
    public const string SignedInAt = "zkd:signed_in";

    /// <summary>An authentication method reference. One claim per value.</summary>
    public const string Amr = "zkd:amr";

    /// <summary>The identifier the user signs in with, when the sign-in gave one.</summary>
    public const string LoginIdentifier = "zkd:login_id";

    /// <summary>A client and the account last signed in to or picked for it, as <c>subject client_id</c>: a subject holds no space.</summary>
    public const string ClientAccount = "zkd:client";
}

/// <summary>One signed-in account's session, read back from the session cookie.</summary>
internal sealed record SsoSessionState
{
    public required string SessionId { get; init; }

    public required string Subject { get; init; }

    /// <summary>When the user authenticated: the <c>auth_time</c> that <c>max_age</c> is judged against.</summary>
    public required DateTimeOffset AuthTime { get; init; }

    /// <summary>When this browser last signed the account in, which its lifetime runs from; never before <see cref="AuthTime"/>.</summary>
    public required DateTimeOffset SignedInAt { get; init; }

    public required IReadOnlyList<string> Amr { get; init; }

    /// <summary>The identifier the sign-in gave, or <see langword="null"/> when it gave none.</summary>
    public string? LoginIdentifier { get; init; }

    /// <summary>
    /// Whether a client's <c>login_hint</c> names this account: its login identifier ignoring case,
    /// as an email address is typed, or its subject exactly.
    /// </summary>
    public bool MatchesLoginHint(string loginHint) =>
        (LoginIdentifier is not null && string.Equals(LoginIdentifier, loginHint, StringComparison.OrdinalIgnoreCase))
        || string.Equals(Subject, loginHint, StringComparison.Ordinal);
}

/// <summary>A client, and the account last signed in to or picked for it.</summary>
internal sealed record ClientAccount(string ClientId, string Subject);

/// <summary>
/// The accounts one browser is signed in to, the one most recently signed in to or chosen first,
/// and the account last signed in to or picked for each client, the most recent first.
/// </summary>
internal sealed class SsoSessionList(IReadOnlyList<SsoSessionState> accounts, IReadOnlyList<ClientAccount> clients)
{
    public static SsoSessionList Empty { get; } = new([], []);

    public IReadOnlyList<SsoSessionState> Accounts { get; } = accounts;

    public IReadOnlyList<ClientAccount> Clients { get; } = clients;

    public bool IsEmpty => Accounts.Count == 0;

    /// <summary>The account signed in as <paramref name="subject"/>, or <see langword="null"/>.</summary>
    public SsoSessionState? Find(string subject) =>
        Accounts.FirstOrDefault(account => string.Equals(account.Subject, subject, StringComparison.Ordinal));

    /// <summary>
    /// The account that answers an authorization request: the one its <c>id_token_hint</c> names,
    /// else the one its <c>login_hint</c> names, else the client's own. <see langword="null"/> when a
    /// hint names no account here, and that user must sign in (OIDC Core §3.1.2.1, §3.1.2.2).
    /// </summary>
    public SsoSessionState? Select(string clientId, string? requiredSubject, string? loginHint)
    {
        if (requiredSubject is not null)
            return Find(requiredSubject);

        if (loginHint is not null)
            return Accounts.FirstOrDefault(account => account.MatchesLoginHint(loginHint));

        return DefaultFor(clientId);
    }

    /// <summary>
    /// The account last signed in to or picked for <paramref name="clientId"/>, else the one most recently
    /// signed in to; <see langword="null"/> when the browser holds none.
    /// </summary>
    public SsoSessionState? DefaultFor(string? clientId)
    {
        var remembered = Clients.FirstOrDefault(client => string.Equals(client.ClientId, clientId, StringComparison.Ordinal));

        return (remembered is null ? null : Find(remembered.Subject)) ?? Accounts.MaxBy(account => account.SignedInAt);
    }
}

/// <summary>
/// Reads and writes the SSO session, which <em>is</em> the <c>zkd.session</c> cookie: there is no
/// server-side record. The cookie holds every account the browser is signed in to, each with its
/// own session identifier, authentication time and sign-in time.
/// </summary>
/// <remarks>
/// The cookie is rewritten on every promotion against session fixation; an account's session
/// identifier survives its re-authentication, so what is bound to it stays bound. An account lives
/// for the session cookie's lifetime from its own last sign-in, however often the cookie is
/// rewritten for another, and however long before that sign-in the page says the user authenticated.
/// </remarks>
internal sealed class SsoSession(
    TimeProvider timeProvider,
    IOptions<AuthorizationServerOptions> options,
    IOptionsMonitor<CookieAuthenticationOptions> cookieOptions)
{
    /// <summary>The most clients one browser remembers an account for; the least recently answered is forgotten first.</summary>
    internal const int MaxRememberedClients = 20;

    private const string SubjectClaimType = "sub";

    private const string ClientsIdentityType = "zkd.session.clients";

    private int MaxAccounts => options.Value.AuthorizationEndpoint.Interaction.MaxSignedInAccounts;

    private TimeSpan Lifetime => cookieOptions.Get(ZeeKayDaCookies.Session).ExpireTimeSpan;

    /// <summary>The accounts this browser is signed in to; <see cref="SsoSessionList.Empty"/> without a readable cookie.</summary>
    public async Task<SsoSessionList> ReadAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var result = await context.AuthenticateAsync(ZeeKayDaCookies.Session).ConfigureAwait(false);
        if (!result.Succeeded || result.Principal is null)
            return SsoSessionList.Empty;

        var now = timeProvider.GetUtcNow();
        var accounts = result.Principal.Identities
            .Where(identity => identity.AuthenticationType == ZeeKayDaCookies.Session)
            .Select(ReadAccount)
            .OfType<SsoSessionState>()
            .Where(account => now < account.SignedInAt + Lifetime);

        var clients = result.Principal.Identities
            .Where(identity => identity.AuthenticationType == ClientsIdentityType)
            .SelectMany(identity => identity.FindAll(SsoSessionClaimTypes.ClientAccount))
            .Select(ReadClient)
            .OfType<ClientAccount>();

        return Trim(accounts, clients);
    }

    /// <summary>
    /// Signs the account in: alone, replacing every account held, or beside them when the sign-in's
    /// placement adds. The account keeps its session identifier if the browser already held it, takes
    /// the login identifier this sign-in gave or none, and becomes the one <paramref name="clientId"/>
    /// is answered for.
    /// </summary>
    public async Task<SsoSessionState> PromoteAsync(HttpContext context, SignIn signIn, string clientId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(signIn);
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var current = await ReadAsync(context).ConfigureAwait(false);
        var subject = signIn.Subject.Value;
        var held = current.Find(subject);
        var now = timeProvider.GetUtcNow();

        var account = new SsoSessionState
        {
            SessionId = held?.SessionId ?? StoreKeyGenerator.Generate(),
            Subject = subject,
            AuthTime = signIn.AuthenticatedAt < now ? signIn.AuthenticatedAt.Value : now,
            SignedInAt = now,
            Amr = [.. signIn.AuthenticationMethods],
            LoginIdentifier = signIn.Placement.LoginIdentifier,
        };

        var others = signIn.Placement.AddAccount ? Without(current.Accounts, account) : [];
        await WriteAsync(context, Trim([account, .. others], [new ClientAccount(clientId, subject), .. current.Clients])).ConfigureAwait(false);

        return account;
    }

    /// <summary>
    /// Makes <paramref name="account"/> the one <paramref name="clientId"/> is answered for, and the
    /// most recently chosen. Writes nothing when it already is the client's.
    /// </summary>
    public async Task ChooseAsync(HttpContext context, SsoSessionList current, SsoSessionState account, string clientId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(account);
        ArgumentException.ThrowIfNullOrEmpty(clientId);

        var remembered = current.Clients.FirstOrDefault(client => string.Equals(client.ClientId, clientId, StringComparison.Ordinal));
        if (remembered is not null && string.Equals(remembered.Subject, account.Subject, StringComparison.Ordinal))
            return;

        var accounts = Trim([account, .. Without(current.Accounts, account)], [new ClientAccount(clientId, account.Subject), .. current.Clients]);
        await WriteAsync(context, accounts).ConfigureAwait(false);
    }

    /// <summary>Signs out <paramref name="ended"/>; the cookie goes with the last account.</summary>
    public async Task EndAsync(HttpContext context, SsoSessionList current, SsoSessionState ended)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(ended);

        var remaining = current.Accounts
            .Where(account => !string.Equals(account.SessionId, ended.SessionId, StringComparison.Ordinal))
            .ToArray();

        if (remaining.Length == 0)
        {
            await context.SignOutAsync(ZeeKayDaCookies.Session).ConfigureAwait(false);
            return;
        }

        await WriteAsync(context, Trim(remaining, current.Clients)).ConfigureAwait(false);
    }

    /// <summary>
    /// The list as the cookie may hold it: one entry per subject, at most <c>MaxSignedInAccounts</c>
    /// accounts and <see cref="MaxRememberedClients"/> clients, the least recent dropped, and only
    /// clients whose account is still held.
    /// </summary>
    private SsoSessionList Trim(IEnumerable<SsoSessionState> accounts, IEnumerable<ClientAccount> clients)
    {
        var kept = accounts
            .DistinctBy(account => account.Subject, StringComparer.Ordinal)
            .Take(MaxAccounts)
            .ToArray();

        var remembered = clients
            .Where(client => kept.Any(account => string.Equals(account.Subject, client.Subject, StringComparison.Ordinal)))
            .DistinctBy(client => client.ClientId, StringComparer.Ordinal)
            .Take(MaxRememberedClients)
            .ToArray();

        return new SsoSessionList(kept, remembered);
    }

    private static IEnumerable<SsoSessionState> Without(IEnumerable<SsoSessionState> accounts, SsoSessionState excluded) =>
        accounts.Where(account => !string.Equals(account.Subject, excluded.Subject, StringComparison.Ordinal));

    /// <summary>
    /// Writes the list, expiring with its most recently signed-in account: a write for a choice or a
    /// sign-out never lengthens any account's life.
    /// </summary>
    private async Task WriteAsync(HttpContext context, SsoSessionList list)
    {
        ClaimsIdentity[] identities =
        [
            .. list.Accounts.Select(BuildAccountIdentity),
            .. list.Clients.Count == 0 ? [] : new[] { BuildClientsIdentity(list.Clients) },
        ];

        var properties = new AuthenticationProperties
        {
            IsPersistent = false,
            IssuedUtc = timeProvider.GetUtcNow(),
            ExpiresUtc = list.Accounts.Max(account => account.SignedInAt) + Lifetime,
        };

        await context.SignInAsync(ZeeKayDaCookies.Session, new ClaimsPrincipal(identities), properties).ConfigureAwait(false);
    }

    /// <summary>Exactly the claims <see cref="ReadAccount"/> reads, and nothing else.</summary>
    private static ClaimsIdentity BuildAccountIdentity(SsoSessionState state)
    {
        Claim[] claims =
        [
            new(SubjectClaimType, state.Subject),
            new(SsoSessionClaimTypes.SessionId, state.SessionId),
            new(SsoSessionClaimTypes.AuthTime, state.AuthTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
            new(SsoSessionClaimTypes.SignedInAt, state.SignedInAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
            .. state.Amr.Select(value => new Claim(SsoSessionClaimTypes.Amr, value)),
            .. state.LoginIdentifier is { } loginIdentifier ? [new Claim(SsoSessionClaimTypes.LoginIdentifier, loginIdentifier)] : Array.Empty<Claim>(),
        ];

        return new ClaimsIdentity(claims, ZeeKayDaCookies.Session);
    }

    private static ClaimsIdentity BuildClientsIdentity(IEnumerable<ClientAccount> clients) =>
        new(clients.Select(client => new Claim(SsoSessionClaimTypes.ClientAccount, $"{client.Subject} {client.ClientId}")), ClientsIdentityType);

    /// <summary>The account an identity holds, or <see langword="null"/> without a readable identifier, subject and times.</summary>
    private static SsoSessionState? ReadAccount(ClaimsIdentity identity)
    {
        var sessionId = identity.FindFirst(SsoSessionClaimTypes.SessionId)?.Value;
        var subject = identity.FindFirst(SubjectClaimType)?.Value;
        if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(subject)
            || ReadTime(identity, SsoSessionClaimTypes.AuthTime) is not { } authTime
            || ReadTime(identity, SsoSessionClaimTypes.SignedInAt) is not { } signedInAt)
        {
            return null;
        }

        return new SsoSessionState
        {
            SessionId = sessionId,
            Subject = subject,
            AuthTime = authTime,
            SignedInAt = signedInAt,
            Amr = identity.FindAll(SsoSessionClaimTypes.Amr).Select(claim => claim.Value).ToArray(),
            LoginIdentifier = identity.FindFirst(SsoSessionClaimTypes.LoginIdentifier)?.Value is { Length: > 0 } loginIdentifier ? loginIdentifier : null,
        };
    }

    private static ClientAccount? ReadClient(Claim claim)
    {
        var value = claim.Value;
        var separator = value.IndexOf(' ', StringComparison.Ordinal);

        return separator > 0 && separator < value.Length - 1
            ? new ClientAccount(value[(separator + 1)..], value[..separator])
            : null;
    }

    private static DateTimeOffset? ReadTime(ClaimsIdentity identity, string claimType)
    {
        var value = identity.FindFirst(claimType)?.Value;

        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}
