# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING: `TokenEndpoint.AuthMethodsSupported` is now `ICollection<string>`** (#115)

  `TokenEndpointOptions.AuthMethodsSupported` changes from `ICollection<TokenEndpointAuthMethod>` to
  `ICollection<string>`, and `OpenIdConfigurationDocument.TokenEndpointAuthMethodsSupported` changes
  from `IReadOnlyCollection<TokenEndpointAuthMethod>` to `IReadOnlyCollection<string>`.

  Use the `TokenEndpointAuthMethods` string constants (`ClientSecretBasic`, `ClientSecretPost`,
  `None`) in place of the enum values. Custom authentication methods (e.g. `"tls_client_auth"`) can
  now be included as plain strings alongside these constants.

  The `TokenEndpointAuthMethod` enum is removed entirely.

  Startup validation now enforces that every entry is a non-empty, non-whitespace string with no
  leading/trailing whitespace and no control characters.

- **Harden discovery/protocol endpoint responses with configurable CORS + defensive headers** (#73)

  Discovery responses now support an optional immutable CORS allowlist via
  `DiscoveryDocument.CorsOrigins` (wildcard when empty; strict allowlist matching when configured).
  Startup validation canonicalizes and deduplicates origins, rejects invalid entries, and enforces
  HTTPS by default (HTTP loopback only when `AllowInsecureIssuer = true`).

  ZeeKayDa.Auth protocol endpoints now emit defensive headers via `SecurityHeaders` options:
  `X-Content-Type-Options`, `Referrer-Policy`, and `Cross-Origin-Resource-Policy`, plus
  `X-ZeeKayDa-Insecure-Issuer: true` when insecure issuer mode is enabled for local development.

- **BREAKING: Remove hybrid response type `code id_token` from `ResponseType`** (#29)

  ZeeKayDa.Auth now exposes authorization code flow only. `ResponseType.CodeIdToken` has been
  removed from the public enum, related discovery test coverage has been updated, and the
  configuration docs now state that hybrid and implicit response types are unsupported.

- **BREAKING: Refactor `AuthorizationServerOptions` into grouped nested options** (#51)
  
  `AuthorizationServerOptions` is reshaped from a flat class into grouped nested options aligned with the OIDC Discovery 1.0 specification structure. Grouping mirrors the spec's naming conventions (e.g., `token_endpoint_*` fields group under `TokenEndpoint`, `id_token_*` fields group under `IdToken`). Get-only group properties prevent nulling and preserve framework invariants.

  **Migration table (old → new property paths):**

  | Old (flat) | New (grouped) | Notes |
  |---|---|---|
  | `Issuer` | `Issuer` | Unchanged (server-wide) |
  | `AllowInsecureIssuer` | `AllowInsecureIssuer` | Unchanged (server-wide) |
  | `AuthorizationEndpoint` | `AuthorizationEndpoint.Uri` | Moved into group |
  | `TokenEndpoint` | `TokenEndpoint.Uri` | Moved into group |
  | `JwksUri` | `JwksEndpoint.Uri` | Moved into group |
  | `ResponseTypesSupported` | `Response.TypesSupported` | Moved into new group |
  | `ResponseModesSupported` | `Response.ModesSupported` | Moved into new group |
  | `GrantTypesSupported` | `GrantTypesSupported` | Unchanged (server-wide) |
  | `TokenEndpointAuthMethodsSupported` | `TokenEndpoint.AuthMethodsSupported` | Moved into group |
  | `IdTokenSigningAlgValuesSupported` | `IdToken.SigningAlgValuesSupported` | Moved into new group |
  | `DiscoveryDocumentCacheMaxAgeSeconds` | `DiscoveryDocument.CacheMaxAgeSeconds` | Moved into new group |

  **Example migration:**

  Before:
  ```csharp
  services.AddZeeKayDaAuth(opts =>
  {
      opts.Issuer = "https://auth.example.com";
      opts.TokenEndpoint = "https://custom.example.com/token";
      opts.ResponseTypesSupported = [ResponseType.Code];
      opts.TokenEndpointAuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
  });
  ```

  After:
  ```csharp
  services.AddZeeKayDaAuth(opts =>
  {
      opts.Issuer = "https://auth.example.com";
      opts.TokenEndpoint.Uri = "https://custom.example.com/token";
      opts.Response.TypesSupported = [ResponseType.Code];
      opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
  });
  ```

- **Add new validation rules for token endpoint client authentication** (per ADR 0002)
  - `TokenEndpoint.AuthMethodsSupported` must not be null or empty
  - `TokenEndpoint.AuthMethodsSupported` must contain at least one non-`None` method if `GrantTypesSupported` includes `ClientCredentials` (RFC 6749 §4.4 compliance)

[unreleased]: https://github.com/ChrisKlug/zeekayda-auth/compare/HEAD...HEAD
