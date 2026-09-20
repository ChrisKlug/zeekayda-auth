# Conformance results

Run of the OpenID Foundation conformance suite against the sample identity server, 2026-09-19,
suite `release-v5.3.1`; the basic plan was re-run the same day once #732 made `nonce` optional.
Reproduce from the repository root with `./conformance/run-conformance.sh`; rewrite this file when
the numbers change.

## Headline

**Both certification plans run to completion and the run exits zero against the manifests in
`expected/`.** Of the basic plan's 35 modules, 23 pass outright, 4 finish in the suite's review state
with the screenshot it wants captured automatically, 5 carry a warning, 1 fails and 2 are skipped.
Every warning, failure and skip is listed below with its cause and the issue that removes it.

The one setup change that made this possible: the two conformance clients are registered with
`RequirePkce` set to `false` (OAuth 2.1 §7.5.1.1; the setting was then named
`AllowNonceInsteadOfPkce`). The plan's modules send no `code_challenge`, and without the opt-out
every module was refused at the authorization endpoint and the runner aborted after three
interruptions in a row. The suite has no switch to make the basic plan send PKCE; only the one
dedicated PKCE module does.

## Timing

Measured on a developer machine with the suite clone and images present, wall clock from script
start to teardown:

| Run | Wall clock | Of which the plan itself |
|---|---:|---:|
| `config` | 46 s | 0.8 s |
| `basic` | 2 min 13 s | 91 s |
| `all` (both plans) | 2 min 11 s | 92 s |

The fixed cost is about 40 s: waiting for the Java server, building and starting the sample, and
teardown. Of the basic plan's 91 s, 32 s is `oidcc-codereuse-30seconds` deliberately waiting before
replaying a code. The 4 review-state modules used to stall for 240 s each until the runner gave up;
the per-module browser overrides in `config/zeekayda.json` now capture the page the suite wants a
screenshot of, so they finish in a few seconds.

## `oidcc-config-certification-test-plan`

| Module | Result | Conditions |
|---|---|---|
| `oidcc-discovery-endpoint-verification` | WARNING | 32 success, 1 warning, 0 failure |

| Warning | Triage |
|---|---|
| `OIDCCCheckDiscEndpointClaimsSupported` — *claims_supported: not found* | **Fixed by #716**, which added `claims_supported`. The result above is from the run that found it; the numbers here are rewritten the next time the suite is run against the sample, not by the change that fixed the gap. Its entry in `conformance/expected/config.failures.json` is gone, so a run that still reports this warning now fails the check. |

The discovery document **as recorded by that run**, before #716 added `claims_supported`. It is a
snapshot of what was served at the time, not a current field list; the next run against the sample
rewrites it:

```
issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri, end_session_endpoint,
response_types_supported=[code], response_modes_supported=[query],
grant_types_supported=[authorization_code], scopes_supported=[openid,profile,email,phone,address],
token_endpoint_auth_methods_supported=[client_secret_basic,none],
subject_types_supported=[public], id_token_signing_alg_values_supported=[RS256],
code_challenge_methods_supported=[S256]
```

## `oidcc-basic-certification-test-plan`

35 modules, all run. Conditions across the plan: 1750 success, 5 warning, 1 failure.

| # | Module | Result |
|---:|---|---|
| 1 | `oidcc-server` | PASSED |
| 2 | `oidcc-response-type-missing` | PASSED |
| 3 | `oidcc-userinfo-get` | PASSED |
| 4 | `oidcc-userinfo-post-header` | PASSED |
| 5 | `oidcc-userinfo-post-body` | PASSED |
| 6 | `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | PASSED |
| 7 | `oidcc-scope-profile` | PASSED |
| 8 | `oidcc-scope-email` | WARNING — C |
| 9 | `oidcc-scope-address` | PASSED |
| 10 | `oidcc-scope-phone` | PASSED |
| 11 | `oidcc-scope-all` | PASSED |
| 12 | `oidcc-alternate-happy-flow` | WARNING — C |
| 13 | `oidcc-display-page` | PASSED |
| 14 | `oidcc-display-popup` | PASSED |
| 15 | `oidcc-prompt-login` | REVIEW — second login page captured |
| 16 | `oidcc-prompt-none-not-logged-in` | PASSED |
| 17 | `oidcc-prompt-none-logged-in` | PASSED |
| 18 | `oidcc-max-age-1` | REVIEW — second login page captured |
| 19 | `oidcc-max-age-10000` | PASSED |
| 20 | `oidcc-ensure-request-with-unknown-parameter-succeeds` | PASSED |
| 21 | `oidcc-id-token-hint` | PASSED |
| 22 | `oidcc-login-hint` | PASSED |
| 23 | `oidcc-ui-locales` | PASSED |
| 24 | `oidcc-claims-locales` | PASSED |
| 25 | `oidcc-ensure-request-with-acr-values-succeeds` | WARNING — D |
| 26 | `oidcc-codereuse` | PASSED |
| 27 | `oidcc-codereuse-30seconds` | WARNING — E |
| 28 | `oidcc-ensure-registered-redirect-uri` | REVIEW — error page captured |
| 29 | `oidcc-ensure-post-request-succeeds` | PASSED |
| 30 | `oidcc-server-client-secret-post` | **FAILED** — B |
| 31 | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | SKIPPED — G |
| 32 | `oidcc-claims-essential` | WARNING — F |
| 33 | `oidcc-ensure-request-object-with-redirect-uri` | REVIEW — error page captured |
| 34 | `oidcc-refresh-token` | SKIPPED — H |
| 35 | `oidcc-ensure-request-with-valid-pkce-succeeds` | PASSED |

REVIEW is the suite's status for a module whose checks all passed and which additionally holds a
screenshot for a human certifier to look at. Nothing in a REVIEW module failed.

### Failures

- **B — harness and sample, #717.** `GetStaticClientConfiguration`: the module wants a
  `client_secret_post` block in the suite config naming a client that authenticates that way, and
  the sample advertises only `client_secret_basic` and `none`.

### Warnings

- **C — library, #734.** `EnsureIdTokenDoesNotContainEmailForScopeEmail`: the code flow's ID token
  carries `email`. OIDC Core §5.4 routes the standard scopes' claims to userinfo when an access
  token is issued; the framework ships them in both places today, and #734 changes that default.
- **D — library, #735.** `ValidateIdTokenACRClaimAgainstAcrValuesRequest`: `acr_values` was
  requested and the ID token has no `acr` (OIDC Core §3.1.2.1, SHOULD). The framework carries `acr`
  from the authorization code into the tokens, but the sign-in API gives a login no way to assert
  one, so nothing ever sets it.
- **E — library, #539.** `EnsureHttpStatusCodeIs4xx` after a code replay: RFC 6749 §4.1.2 says the
  server SHOULD revoke tokens issued from the replayed code. The code is burnt and the refresh-token
  family would be revoked, but the access token is a JWT with no revocation path until the
  revocation work in #539.
- **F — library, #736.** `EnsureUserInfoContainsName`: `scope=openid` with
  `claims={"userinfo":{"name":{"essential":true}}}` gets no `name`. The `claims` request parameter is
  deferred by the register and `claims_parameter_supported` is `false`.

### Skips

- **G — permanent for v1.** The authorize endpoint answers `request_not_supported`, which the
  module accepts and skips on. JAR (RFC 9101) is refused in v1 by decision
  (`docs/decisions/authorization-and-interaction.md`).
- **H — post-skeleton, #539.** No refresh token is issued: the `refresh_token` grant is not on an
  executed path yet and the sample advertises only `authorization_code`.

### What changed in the sample for this run

- Both conformance clients set `RequirePkce` to `false` (see the headline). The sample's
  `ClientSettings` gained that property; it is applied to confidential clients only.
- The seeded user carries every OIDC Core §5.4 profile claim. The suite's scope modules expect all
  fourteen at userinfo, and four of them was a warning on `oidcc-scope-profile` and
  `oidcc-scope-all`.

## What was not run

- Everything outside the two OIDC certification plans above: FAPI, CIBA, logout, dynamic client
  registration, and the implicit and hybrid flows. The framework serves `response_types_supported=[code]`
  and has no dynamic registration, so those plans do not apply.
- The suite's RP-against-OP tests, which test a client rather than a server.
