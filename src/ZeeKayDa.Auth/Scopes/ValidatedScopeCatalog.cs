using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// The framework's only path from <see cref="IScopeRepository"/> to scope definitions: copies what it
/// returns, checks the copy against the documented contract, and throws when it is broken.
/// </summary>
/// <remarks>
/// The copy is what is served, so a repository mutating what it returned cannot have one set approved and
/// another issued. Checked on every call with no cache, so an answer that changed after startup is caught.
/// A broken repository throws: no reduced answer is safe.
/// </remarks>
internal sealed class ValidatedScopeCatalog(IScopeRepository repository)
{
    /// <summary>
    /// The scopes the repository serves, copied and checked against the
    /// <see cref="IScopeRepository.GetScopesAsync"/> contract.
    /// </summary>
    /// <exception cref="ScopeContractException">
    /// Thrown when the repository breaks that contract, carrying one
    /// <see cref="ZeeKayDaConfigurationFailure"/> per rule broken so an operator sees every
    /// problem at once rather than one per restart. An exception the repository itself threw is
    /// never absorbed or reworded — see <see cref="ScopeContractException"/> for why the
    /// distinction is load-bearing.
    /// </exception>
    public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken)
    {
        var served = await repository.GetScopesAsync(cancellationToken).ConfigureAwait(false);

        // Reported alone: every check below would also fire against an empty stand-in and bury the cause.
        if (served is null)
        {
            throw new ScopeContractException(new ZeeKayDaConfigurationFailure(
                "scopes.null",
                "IScopeRepository.GetScopesAsync returned null. It must return a collection — an " +
                "empty one if the repository knows no scopes — because every scope rule, the " +
                "discovery document's scopes_supported and the openid-scope requirement all read it."));
        }

        var failures = new List<ZeeKayDaConfigurationFailure>();
        var scopes = Copy(served, failures);

        CheckNamesArePresent(scopes, failures);
        CheckNamesAreScopeTokens(scopes, failures);
        CheckNamesAreUnique(scopes, failures);
        CheckClaims(scopes, failures);
        CheckAudiences(scopes, failures);
        CheckOpenIdIsPresent(scopes, failures);

        return failures.Count == 0
            ? scopes
            : throw new ScopeContractException([.. failures]);
    }

    /// <summary>
    /// An independent copy of every definition, dropping a null element and reading a null claim list as
    /// empty, so later checks need no null guards; both are reported as failures.
    /// </summary>
    private static List<ScopeDefinition> Copy(
        IReadOnlyCollection<ScopeDefinition> served,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        var copies = new List<ScopeDefinition>(served.Count);
        var nullElements = 0;

        foreach (var scope in served)
        {
            if (scope is null)
            {
                nullElements++;
                continue;
            }

            ReportNullClaimLists(scope, failures);

            // `with`, so a property added later is copied too; only the collections can still be mutated.
            copies.Add(scope with
            {
                IdTokenClaims = CopyClaims(scope.IdTokenClaims),
                UserInfoClaims = CopyClaims(scope.UserInfoClaims),
                AccessTokenClaims = CopyClaims(scope.AccessTokenClaims),
            });
        }

        if (nullElements > 0)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.element.null",
                $"IScopeRepository.GetScopesAsync returned {nullElements} null element(s) in its " +
                "collection. Every element must be a scope definition; a repository with nothing " +
                "to serve returns an empty collection rather than a collection of nulls."));
        }

        return copies;
    }

    /// <summary>A claim list as its own array, reading a null list as empty.</summary>
    private static IReadOnlyCollection<string> CopyClaims(IReadOnlyCollection<string>? claims) =>
        claims is null ? [] : [.. claims];

    /// <summary>A failure per claim list the repository served as null, run on the original before the copy.</summary>
    private static void ReportNullClaimLists(ScopeDefinition scope, List<ZeeKayDaConfigurationFailure> failures)
    {
        ReportIfNull(scope, scope.IdTokenClaims, nameof(ScopeDefinition.IdTokenClaims), failures);
        ReportIfNull(scope, scope.UserInfoClaims, nameof(ScopeDefinition.UserInfoClaims), failures);
        ReportIfNull(scope, scope.AccessTokenClaims, nameof(ScopeDefinition.AccessTokenClaims), failures);
    }

    private static void ReportIfNull(
        ScopeDefinition scope,
        IReadOnlyCollection<string>? claims,
        string property,
        List<ZeeKayDaConfigurationFailure> failures)
    {
        if (claims is not null)
            return;

        failures.Add(new ZeeKayDaConfigurationFailure(
            "scopes.claims.blank",
            $"Scope '{scope.Name}' has a null {property} list. ScopeDefinition declares its claim " +
            "lists as never null and defaults each to empty; a scope that unlocks no claims in a " +
            "destination leaves that list empty rather than setting it to null."));
    }

    /// <summary>Every scope is named.</summary>
    private static void CheckNamesArePresent(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes.Where(scope => string.IsNullOrWhiteSpace(scope.Name)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.name.blank",
                "IScopeRepository returned a scope with no name. A scope's name is what a client " +
                "requests and what the discovery document publishes in scopes_supported, which " +
                $"OpenID Connect Discovery 1.0 §3 defines as a list of strings. Scope: '{scope.Name}'."));
        }
    }

    /// <summary>Every named scope is an RFC 6749 §3.3 scope-token, so it cannot split a space-delimited scope list.</summary>
    private static void CheckNamesAreScopeTokens(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes.Where(IsNamedButNotAScopeToken))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.name.invalid",
                $"IScopeRepository returned a scope named '{scope.Name}', which is not a scope-token. RFC 6749 §3.3 " +
                "allows only the printable ASCII characters other than space, '\"' and '\\' in a scope name, since " +
                "the scope parameter and the scope claim are space-delimited lists of names."));
        }
    }

    /// <summary>A blank name is reported as blank, not also as malformed.</summary>
    private static bool IsNamedButNotAScopeToken(ScopeDefinition scope) =>
        !string.IsNullOrWhiteSpace(scope.Name) && !scope.Name.All(IsScopeTokenCharacter);

    /// <summary><c>NQCHAR = %x21 / %x23-5B / %x5D-7E</c> (RFC 6749 Appendix A).</summary>
    private static bool IsScopeTokenCharacter(char c) =>
        c is '!' or (>= '#' and <= '[') or (>= ']' and <= '~');

    /// <summary>
    /// No two scopes share an ordinal name: a duplicate resolves to whichever came first. Two sets rather than
    /// a <c>GroupBy</c>, since this runs on every request; one failure per repeated name.
    /// </summary>
    private static void CheckNamesAreUnique(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var reported = new HashSet<string>(StringComparer.Ordinal);

        var repeated = scopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope.Name))
            .Where(scope => !seen.Add(scope.Name))
            .Where(scope => reported.Add(scope.Name));

        foreach (var scope in repeated)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.name.duplicate",
                $"IScopeRepository returned more than one scope named '{scope.Name}'. A scope name " +
                "must identify one definition: a duplicate resolves to whichever the repository " +
                "happened to return first, deciding the claims it unlocks and the audience its " +
                "access token carries, and scopes_supported publishes the name twice."));
        }
    }

    /// <summary>
    /// Every listed claim is named, at most one failure per scope, and none is a protocol claim the framework
    /// writes from the grant.
    /// </summary>
    private static void CheckClaims(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes)
        {
            if (AllClaimsListedBy(scope).Any(string.IsNullOrWhiteSpace))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "scopes.claims.blank",
                    $"Scope '{scope.Name}' lists a claim with no name. ClaimRecord refuses a null, empty " +
                    "or whitespace claim type, so no claims provider can ever deliver it and selection " +
                    "would carry it for nothing; remove it from the scope."));
            }

            foreach (var claim in ReservedClaimsListedBy(scope))
            {
                failures.Add(new ZeeKayDaConfigurationFailure(
                    "scopes.claims.reserved",
                    $"Scope '{scope.Name}' lists '{claim}', a protocol claim the framework writes from the grant. A " +
                    "claims provider cannot supply it and selection never delivers it; remove it from the scope."));
            }
        }
    }

    /// <summary>A set <see cref="ScopeDefinition.Audience"/> is a resource indicator, since it becomes <c>aud</c> as written.</summary>
    private static void CheckAudiences(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes.Where(scope => scope.Audience is not null && !ResourceIndicator.IsValid(scope.Audience)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.audience.invalid",
                $"Scope '{scope.Name}' has an Audience of '{scope.Audience}', which is not an absolute URI without a " +
                "fragment. RFC 8707 §2 requires both of a resource indicator, and the value becomes the access " +
                "token's aud claim as written."));
        }
    }

    /// <summary>The <c>openid</c> scope is served and advertised in <c>scopes_supported</c>.</summary>
    private static void CheckOpenIdIsPresent(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        var openId = scopes.FirstOrDefault(scope => string.Equals(scope.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal));

        if (openId is null)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.openid_missing",
                $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
                $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'."));
        }
        else if (!openId.IsDiscoverable)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.openid_hidden",
                $"The '{StandardScopes.OpenId.Name}' scope has IsDiscoverable set to false, which omits it from the " +
                "discovery document's scopes_supported. OpenID Connect Discovery 1.0 §3 requires a server to " +
                $"support '{StandardScopes.OpenId.Name}', so scopes_supported must advertise it; set IsDiscoverable to true."));
        }
    }

    /// <summary>Every claim name a scope lists, across all three destinations.</summary>
    private static IEnumerable<string> AllClaimsListedBy(ScopeDefinition scope) =>
        scope.IdTokenClaims.Concat(scope.UserInfoClaims).Concat(scope.AccessTokenClaims);

    /// <summary>The reserved names a scope lists, except <c>sub</c>, which <c>openid</c> lists for readability.</summary>
    private static IEnumerable<string> ReservedClaimsListedBy(ScopeDefinition scope) =>
        AllClaimsListedBy(scope)
            .Where(claim => claim is not null && ReservedClaimNames.IsReserved(claim) && !string.Equals(claim, "sub", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
