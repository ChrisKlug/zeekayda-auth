# Conformance results

First local run of the OpenID Foundation conformance suite against the sample identity server,
2026-09-19. Suite `release-v5.3.1`. Reproduce from the repository root with `./conformance/run-conformance.sh`; rewrite this file when
the numbers change.

## Headline

**The basic certification plan cannot run at all yet.** All 35 of its modules are interrupted
during setup because the server publishes no `userinfo_endpoint`. The config plan runs and is
clean apart from two warnings, one of which is that same missing endpoint.

## `oidcc-config-certification-test-plan`

One module, finished in about a second.

| Module | Result | Conditions |
|---|---|---|
| `oidcc-discovery-endpoint-verification` | WARNING | 30 success, 2 warning, 0 failure |

| Warning | Triage |
|---|---|
| `CheckDiscEndpointUserinfoEndpoint` — *Skipped evaluation due to missing required element: server userinfo_endpoint* | **Library gap**, already tracked by #708. OpenID Connect Core 1.0 §5.3. |
| `OIDCCCheckDiscEndpointClaimsSupported` — *claims_supported: not found* | **Library gap**, filed as #716. OpenID Connect Discovery 1.0 §3 lists `claims_supported` as RECOMMENDED. |

Nothing else in the discovery document drew a complaint. For the record, as served:

```
issuer, authorization_endpoint, token_endpoint, jwks_uri, end_session_endpoint,
response_types_supported=[code], response_modes_supported=[query],
grant_types_supported=[authorization_code], scopes_supported=[openid,profile,email,phone,address],
token_endpoint_auth_methods_supported=[client_secret_basic,none],
subject_types_supported=[public], id_token_signing_alg_values_supported=[RS256],
code_challenge_methods_supported=[S256]
```

## `oidcc-basic-certification-test-plan`

35 modules, **0 run to completion**, in two distinct ways.

### Every module, and why

No module reached the authorization endpoint, so none has a pass, a fail or a skip to report —
`interrupted` is the suite's own status for a module stopped during setup. The two causes:

- **A — library gap.** `SetProtectedResourceUrlToUserInfoEndpoint: userinfo_endpoint missing from
  server configuration. The user info is not a mandatory to implement feature in the OpenID Connect
  specification, but is mandatory for certification.` Tracked by #708.
- **B — harness and sample setup, not a library gap.** `GetStaticClientConfiguration: As static
  client was selected, the test configuration must contain a client configuration` — this module
  wants a `client_secret_post` block naming a client that authenticates that way, and the sample
  advertises only `client_secret_basic` and `none`. Tracked by #717. It is reached at all only
  because the module overrides the setup step that stops the other 34.

| # | Module | Status | Cause |
|---:|---|---|---|
| 1 | `oidcc-server` | interrupted | **A** |
| 2 | `oidcc-response-type-missing` | interrupted | **A** |
| 3 | `oidcc-userinfo-get` | interrupted | **A** |
| 4 | `oidcc-userinfo-post-header` | interrupted | **A** |
| 5 | `oidcc-userinfo-post-body` | interrupted | **A** |
| 6 | `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | interrupted | **A** |
| 7 | `oidcc-scope-profile` | interrupted | **A** |
| 8 | `oidcc-scope-email` | interrupted | **A** |
| 9 | `oidcc-scope-address` | interrupted | **A** |
| 10 | `oidcc-scope-phone` | interrupted | **A** |
| 11 | `oidcc-scope-all` | interrupted | **A** |
| 12 | `oidcc-alternate-happy-flow` | interrupted | **A** |
| 13 | `oidcc-display-page` | interrupted | **A** |
| 14 | `oidcc-display-popup` | interrupted | **A** |
| 15 | `oidcc-prompt-login` | interrupted | **A** |
| 16 | `oidcc-prompt-none-not-logged-in` | interrupted | **A** |
| 17 | `oidcc-prompt-none-logged-in` | interrupted | **A** |
| 18 | `oidcc-max-age-1` | interrupted | **A** |
| 19 | `oidcc-max-age-10000` | interrupted | **A** |
| 20 | `oidcc-ensure-request-with-unknown-parameter-succeeds` | interrupted | **A** |
| 21 | `oidcc-id-token-hint` | interrupted | **A** |
| 22 | `oidcc-login-hint` | interrupted | **A** |
| 23 | `oidcc-ui-locales` | interrupted | **A** |
| 24 | `oidcc-claims-locales` | interrupted | **A** |
| 25 | `oidcc-ensure-request-with-acr-values-succeeds` | interrupted | **A** |
| 26 | `oidcc-codereuse` | interrupted | **A** |
| 27 | `oidcc-codereuse-30seconds` | interrupted | **A** |
| 28 | `oidcc-ensure-registered-redirect-uri` | interrupted | **A** |
| 29 | `oidcc-ensure-post-request-succeeds` | interrupted | **A** |
| 30 | `oidcc-server-client-secret-post` | interrupted | **B** |
| 31 | `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | interrupted | **A** |
| 32 | `oidcc-claims-essential` | interrupted | **A** |
| 33 | `oidcc-ensure-request-object-with-redirect-uri` | interrupted | **A** |
| 34 | `oidcc-refresh-token` | interrupted | **A** |
| 35 | `oidcc-ensure-request-with-valid-pkce-succeeds` | interrupted | **A** |

34 × **A**, 1 × **B**. Re-run and rewrite this table once #708 lands: it is the per-module record
#307 gates against, and the first run where these statuses mean anything about the login flow.

### Why one missing endpoint blocks everything

This is the finding worth carrying away. The userinfo call is not confined to the three userinfo
modules: the suite sets the protected-resource URL in
`AbstractOIDCCServerTest.configureProtectedResourceUrl()`, which every module in the plan inherits,
and it runs during setup before any request reaches the authorization endpoint. So a module testing
`prompt=login`, or code reuse, or an unregistered `redirect_uri` — none of which touch userinfo —
never starts.

The consequence for planning: **no part of the flow is conformance-tested until #708 lands.** Not
partially, not the non-userinfo majority. The suite's certification profile treats userinfo as
mandatory even though the spec does not, and it enforces that in the shared setup rather than per
module.

Nothing here is a newly discovered spec gap in code that was believed to work: the plan never
exercised any of it. Re-run and re-triage this section once #708 lands — that run is the one that
tells us what the flow actually gets wrong.

## What was not run

- Everything outside the two OIDC certification plans above: FAPI, CIBA, logout, dynamic client
  registration, and the implicit and hybrid flows. The framework serves `response_types_supported=[code]`
  and has no dynamic registration, so those plans do not apply.
- The suite's RP-against-OP tests, which test a client rather than a server.
