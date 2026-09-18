# Conformance results

First local run of the OpenID Foundation conformance suite against the sample identity server,
2026-09-18. Suite `release-v5.3.1`. Reproduce with `./run-conformance.sh`; rewrite this file when
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

35 modules, **0 run to completion**. 34 are interrupted by

```
SetProtectedResourceUrlToUserInfoEndpoint: userinfo_endpoint missing from server configuration.
The user info is not a mandatory to implement feature in the OpenID Connect specification, but is
mandatory for certification.
```

and the 35th, `oidcc-server-client-secret-post`, by

```
GetStaticClientConfiguration: As static client was selected, the test configuration must contain a
client configuration
```

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

### Triage

| Finding | Classification | Tracked |
|---|---|---|
| 34 modules interrupted: no `userinfo_endpoint` | **Library gap** — no userinfo endpoint is implemented | #708 |
| `oidcc-server-client-secret-post` interrupted: no `client_secret_post` client in the test config | **Harness and sample setup**, not a library gap — the framework supports the method, the sample advertises only `client_secret_basic` and `none`, and `AuthMethodsSupported` is server-wide | #717 |

Nothing here is a newly discovered spec gap in code that was believed to work: the plan never
exercised any of it. Re-run and re-triage this section once #708 lands — that run is the one that
tells us what the flow actually gets wrong.

## What was not run

- Everything outside the two OIDC certification plans above: FAPI, CIBA, logout, dynamic client
  registration, and the implicit and hybrid flows. The framework serves `response_types_supported=[code]`
  and has no dynamic registration, so those plans do not apply.
- The suite's RP-against-OP tests, which test a client rather than a server.
