# Authorization endpoint interaction

**Status: provisional.** Nothing here is built — `/connect/authorize` answers `501`. Recovered from
ADR 0005 (accepted 2026-07-01, issue #156), which was deleted in the register migration.
The security properties and protocol refusals that came out of this design are in
`docs/decisions/authorization-and-interaction.md` and are *not* repeated here.

## Host registration

The design goal: a host names the providers it wants and nothing else. Callback paths, the schemes
those providers sign into, and the correlation back to the authorization request are the framework's
problem, not the host's. This is the difference from IdentityServer and OpenIddict, where the host
registers providers directly against ASP.NET Core and owns the routing and callback wiring itself.

```csharp
builder.Services
    .AddZeeKayDaAuth(o =>
    {
        o.Issuer = "https://id.example.com";
        o.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
        o.OnSigningIn = async ctx => { /* fires for ALL sign-ins; no interrupt */ };
    })
    .WithLocalAuth(o => o.LoginPath = "/auth/login")
    .WithProviders(
        auth => auth.AddFacebook(o => { }),
        o => o.OnProviderSignIn = async ctx => await ctx.RedirectToAsync("/collect-more"));
```

`WithProviders` hands out a real ASP.NET Core `AuthenticationBuilder`, so every existing provider
package (`AddFacebook`, `AddGoogle`, `AddOpenIdConnect`, …) works unchanged. It then forces
`SignInScheme = "zkd.external"` on every `RemoteAuthenticationOptions`-derived handler it registered,
*after* the host's configuration callback has run, so the host cannot silently redirect the callback
elsewhere.

**Open question.** Whether providers stay on a separate builder call as above, or move inside the
`AddZeeKayDaAuth` options lambda (`o => o.AddFacebook(...).AddGoogle(...)`), which reads better at
the call site but cannot hand out an `AuthenticationBuilder`. Unresolved.

## Callback paths

One path per registered scheme — `/connect/callback/{facebook,bankid,google,…}` — resolved by the
router from the route template. Never a single `/connect/provider-callback?scheme=X`: a query-string
discriminator makes dispatch trust attacker-visible input.

## Internal cookie schemes

`AddZeeKayDaAuth` registers four. Names are reserved; a host registering one fails at startup. All
four are `HttpOnly` and Data-Protection encrypted.

| Scheme | Holds | Lifetime | `SameSite` |
|---|---|---|---|
| `zkd.session` | the SSO session | session | `None` only if `prompt=none` silent auth is supported, else `Lax` |
| `zkd.interaction` | the authorization request context | hard 30 min | `Lax` |
| `zkd.external` | the raw provider callback, before ZeeKayDa reads it | seconds | `Lax` |
| `zkd.pending` | a half-authenticated external principal | hard 15 min, not sliding | `Strict` |

`zkd.pending` is single-use (signed out on `SignInAsync`) and bound to its interaction by a
`zkd:interaction_id` claim, so it cannot complete a different flow.

## Interaction context storage

Default: the encrypted `zkd.interaction` cookie — ~1KB, no server state. Upgrade path:
`.UseDistributedCacheInteractionStore()` replaces the cookie payload with an opaque ~50-byte handle
backed by any `IDistributedCache`, optionally a keyed instance.

## Interaction services

The host's only way to advance the protocol state machine. All terminal methods write the redirect
response and must be the caller's last action — the same contract as `HttpContext.SignInAsync`.

```csharp
public interface IAuthenticationInteraction
{
    // Promotes principal to SSO session, issues code, redirects. Auto-consumes a bound
    // "zkd.pending" cookie if present. Terminal — writes the response.
    // Throws ZeeKayDaInteractionException if no active interaction context exists.
    Task SignInAsync(ClaimsPrincipal principal, string amr);

    // Null if the pending cookie is absent, expired or misbound — caller treats as recoverable.
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}

public interface IConsentInteraction
{
    Task<ConsentRequest> GetRequestAsync();
    Task GrantAsync(IEnumerable<string> grantedScopes); // re-intersects requested ∩ client-allowed
    Task DenyAsync();                                   // redirects with error=access_denied
}
```

## Event model — implicit proceed, explicit interrupts only

`OnProviderSignIn` (external providers only) may call `ctx.RedirectToAsync(path)`, which stores a
pending principal and resumes on `SignInAsync`, or `ctx.DenyAsync(error)`. If it calls neither, the
principal is promoted and the code issued automatically.

`OnSigningIn` fires for every sign-in path immediately before promotion, has no interrupt capability,
and receives a clone of the principal the host may freely mutate. Reserved protocol claims (`iss`,
`sub`, `aud`, `exp`, `nonce`, `acr`, `amr`, `zkd:*`) are stripped before issuance regardless.

## Rejected

- **A routed minimal-API endpoint for `/connect/authorize`.** It cannot stop downstream middleware
  from observing the request. (The ADR also claimed a routed endpoint cannot serve both GET and POST
  — that reason is wrong, `MapMethods` does exactly that, and it is not what carries the decision.)
- **A single callback path with a `?scheme=X` discriminator.** Forces dispatch on attacker-visible
  input; per-scheme paths also produce cleaner audit logs.
- **ZeeKayDa owning the interaction UI** — a "black box" framework rendering its own login and
  consent pages. It would take away the host's user model, identity store, branding and MFA, and
  couple the framework to a UI stack.
- **Full delegation to `ChallengeAsync` plus a session cookie, with no framework-owned interaction
  context.** Breaks as soon as a flow needs more than one interactive step: without an owned
  context, a returning authenticated user cannot be correlated with the authorization request they
  were completing, especially across concurrent tabs.
- **Merging `zkd.external` and `zkd.pending` into one scheme.** Would push binding-claim logic into
  the common no-redirect path, which never needs a pending cookie at all. The external handler signs
  in before ZeeKayDa can attach the binding claim, so one scheme cannot carry both jobs.
- **A `CompleteAsync` method separate from `SignInAsync`.** Cognitive load with no benefit —
  `SignInAsync` detects and consumes a pending cookie by itself.
- **A bespoke `IAuthorizationInteractionStore` interface.** `IDistributedCache` already covers Redis,
  SQL Server and custom backends; a new interface would be another name for the same contract.
