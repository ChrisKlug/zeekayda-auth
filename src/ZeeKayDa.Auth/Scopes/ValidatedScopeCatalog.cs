using ZeeKayDa.Auth.Claims;

namespace ZeeKayDa.Auth.Scopes;

/// <summary>
/// The framework's only path from <see cref="IScopeRepository"/> to a scope definition. Copies
/// what the repository returned and refuses the copy, with a
/// <see cref="ZeeKayDaConfigurationException"/>, when it breaks the contract
/// <see cref="IScopeRepository.GetScopesAsync"/> documents.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ScopeDefinition"/> declares a name and three claim lists that are never null, and
/// <see cref="InMemoryScopeRepository"/> refuses a blank, duplicated or unnamed entry in its
/// constructor — but a custom <see cref="IScopeRepository"/> runs neither that constructor nor the
/// nullable annotations, which are not enforced at runtime. Consumers had each been defending
/// themselves instead, reading a null claim list as empty in four separate places, which keeps the
/// process up and tells the operator nothing. This type makes the guarantee structural: every
/// consumer takes the catalog, never the repository.
/// </para>
/// <para>
/// <strong>What is validated is what is served.</strong> Each definition is copied, claim lists
/// included, before it is checked, and it is the copy that is returned. A repository free to
/// mutate what it handed back would otherwise have one set of scopes approved and a different set
/// used to issue a token.
/// </para>
/// <para>
/// <strong>Validated on every call, with no cache.</strong> Unlike
/// <c>ValidatedClientResolver</c>, whose verdicts are memoized because validation runs a PBKDF2
/// derivation, the work here is a linear pass over a handful of definitions. A cache would buy
/// nothing and would hide a repository whose answer changed after startup — which is the gap that
/// checking at startup alone leaves open.
/// </para>
/// <para>
/// A broken repository throws rather than degrading. There is no safe reduced answer: serving no
/// scopes would fail the client's request with <c>invalid_scope</c> for what is the operator's
/// bug, and serving the scopes that happen to be well-formed would issue tokens against half a
/// configuration. At startup <c>ScopePresenceStartupValidator</c> turns the same failures into
/// named startup failures, so a misconfigured host does not reach a request at all.
/// </para>
/// </remarks>
internal sealed class ValidatedScopeCatalog
{
    private readonly IScopeRepository _repository;

    public ValidatedScopeCatalog(IScopeRepository repository)
    {
        ArgumentNullException.ThrowIfNull(repository);

        _repository = repository;
    }

    /// <summary>
    /// The scopes the repository serves, copied and checked against the
    /// <see cref="IScopeRepository.GetScopesAsync"/> contract.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the repository breaks that contract, carrying one
    /// <see cref="ZeeKayDaConfigurationFailure"/> per rule broken so an operator sees every
    /// problem at once rather than one per restart.
    /// </exception>
    public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken)
    {
        var served = await _repository.GetScopesAsync(cancellationToken).ConfigureAwait(false);

        // A null collection is reported alone. Every check below would fire against the empty
        // list that stands in for it — "the openid scope is missing" above all — and an operator
        // reading a list of consequences has to work out which one is the cause.
        if (served is null)
        {
            throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure(
                "scopes.null",
                "IScopeRepository.GetScopesAsync returned null. It must return a collection — an " +
                "empty one if the repository knows no scopes — because every scope rule, the " +
                "discovery document's scopes_supported and the openid-scope requirement all read it."));
        }

        var failures = new List<ZeeKayDaConfigurationFailure>();
        var scopes = Copy(served, failures);

        CheckNames(scopes, failures);
        CheckClaims(scopes, failures);
        CheckAudiences(scopes, failures);
        CheckOpenIdIsPresent(scopes, failures);

        return failures.Count == 0
            ? scopes
            : throw new ZeeKayDaConfigurationException([.. failures]);
    }

    /// <summary>
    /// An independent copy of every definition the repository served, with a failure recorded for
    /// a null element. A null element is dropped rather than carried, so the checks below read a
    /// list they can dereference; the failure is what the operator acts on.
    /// </summary>
    /// <remarks>
    /// A null claim list is copied as empty rather than thrown on here, because
    /// <see cref="CheckClaims"/> reports it as the named failure it is. Copying it first keeps
    /// every later check able to enumerate the list without a null guard of its own — the guards
    /// this type exists to remove.
    /// </remarks>
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

            copies.Add(new ScopeDefinition
            {
                Name = scope.Name,
                IsDiscoverable = scope.IsDiscoverable,
                IdTokenClaims = CopyClaims(scope.IdTokenClaims),
                UserInfoClaims = CopyClaims(scope.UserInfoClaims),
                AccessTokenClaims = CopyClaims(scope.AccessTokenClaims),
                Audience = scope.Audience,
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

    /// <summary>
    /// A claim list as its own array, reading a null list as empty. The null is reported by
    /// <see cref="ReportNullClaimLists"/>, which runs against the same original definition.
    /// </summary>
    private static IReadOnlyCollection<string> CopyClaims(IReadOnlyCollection<string>? claims) =>
        claims is null ? [] : [.. claims];

    /// <summary>
    /// A failure for each destination whose claim list the repository served as null, named as the
    /// property an operator would go and fix.
    /// </summary>
    /// <remarks>
    /// Runs against the definition the repository served, before the copy substitutes an empty
    /// list for each — which is what lets every check after this one enumerate a claim list
    /// without a null guard of its own.
    /// </remarks>
    private static void ReportNullClaimLists(ScopeDefinition scope, List<ZeeKayDaConfigurationFailure> failures)
    {
        var nullLists = new[]
        {
            (nameof(ScopeDefinition.IdTokenClaims), scope.IdTokenClaims),
            (nameof(ScopeDefinition.UserInfoClaims), scope.UserInfoClaims),
            (nameof(ScopeDefinition.AccessTokenClaims), scope.AccessTokenClaims),
        }.Where(list => list.Item2 is null);

        foreach (var (property, _) in nullLists)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.claims.blank",
                $"Scope '{scope.Name}' has a null {property} list. ScopeDefinition declares its claim " +
                "lists as never null and defaults each to empty; a scope that unlocks no claims in a " +
                "destination leaves that list empty rather than setting it to null."));
        }
    }

    /// <summary>
    /// Every scope is named, and no two share a name. Names are compared ordinally because that
    /// is how a requested scope is matched (<see cref="ScopeResolution.TryResolve"/>) and how the
    /// discovery document publishes them.
    /// </summary>
    /// <remarks>
    /// Two scopes with one name resolve ambiguously — whichever the repository happens to return
    /// first wins, and it decides the claims unlocked and the audience the access token carries.
    /// Both are also published to <c>scopes_supported</c>, which then names the same scope twice.
    /// </remarks>
    private static void CheckNames(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes.Where(scope => string.IsNullOrWhiteSpace(scope.Name)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.name.blank",
                "IScopeRepository returned a scope with no name. A scope's name is what a client " +
                "requests and what the discovery document publishes in scopes_supported, which " +
                $"OpenID Connect Discovery 1.0 §3 defines as a list of strings. Scope: '{scope.Name}'."));
        }

        var duplicates = scopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope.Name))
            .GroupBy(scope => scope.Name, StringComparer.Ordinal)
            .Where(group => group.Count() > 1);

        foreach (var duplicate in duplicates)
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.name.duplicate",
                $"IScopeRepository returned {duplicate.Count()} scopes named '{duplicate.Key}'. A scope " +
                "name must identify one definition: a duplicate resolves to whichever the repository " +
                "happened to return first, deciding the claims it unlocks and the audience its access " +
                "token carries, and scopes_supported publishes the name twice."));
        }
    }

    /// <summary>
    /// Every claim a scope lists is named, and none names a protocol claim the framework writes
    /// from the grant. A null list is reported during the copy, by
    /// <see cref="ReportNullClaimLists"/>.
    /// </summary>
    /// <remarks>
    /// At most one blank-claim failure per scope: the failure says the scope lists an unnamed
    /// claim, and repeating it per blank entry tells the operator nothing new about the same fix.
    /// </remarks>
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

    /// <summary>
    /// An <see cref="ScopeDefinition.Audience"/> that is set is a resource indicator, because the
    /// value becomes the access token's <c>aud</c> claim as written.
    /// </summary>
    private static void CheckAudiences(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        foreach (var scope in scopes.Where(scope => scope.Audience is not null && !ScopeResolution.IsResourceIndicator(scope.Audience)))
        {
            failures.Add(new ZeeKayDaConfigurationFailure(
                "scopes.audience.invalid",
                $"Scope '{scope.Name}' has an Audience of '{scope.Audience}', which is not an absolute URI without a " +
                "fragment. RFC 8707 §2 requires both of a resource indicator, and the value becomes the access " +
                "token's aud claim as written."));
        }
    }

    private static void CheckOpenIdIsPresent(List<ScopeDefinition> scopes, List<ZeeKayDaConfigurationFailure> failures)
    {
        if (scopes.Any(scope => string.Equals(scope.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal)))
            return;

        failures.Add(new ZeeKayDaConfigurationFailure(
            "scopes.openid_missing",
            $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
            $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'."));
    }

    /// <summary>Every claim name a scope lists, across all three destinations.</summary>
    private static IEnumerable<string> AllClaimsListedBy(ScopeDefinition scope) =>
        scope.IdTokenClaims.Concat(scope.UserInfoClaims).Concat(scope.AccessTokenClaims);

    /// <summary>
    /// Every reserved protocol name a scope's lists carry, except <c>sub</c>, which the standard
    /// <c>openid</c> scope lists for readability and which every token carries regardless.
    /// </summary>
    private static IEnumerable<string> ReservedClaimsListedBy(ScopeDefinition scope) =>
        AllClaimsListedBy(scope)
            .Where(claim => claim is not null && ReservedClaimNames.IsReserved(claim) && !string.Equals(claim, "sub", StringComparison.Ordinal))
            .Distinct(StringComparer.OrdinalIgnoreCase);
}
