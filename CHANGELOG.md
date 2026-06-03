# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING: Refactor `AuthorizationServerOptions` into grouped nested options** (#51)
  
  `AuthorizationServerOptions` is reshaped from a flat class into grouped nested options aligned with the OIDC Discovery 1.0 specification structure. Grouping mirrors the spec's naming conventions (e.g., `token_endpoint_*` fields group under `Token`, `id_token_*` fields group under `IdToken`). Get-only group properties prevent nulling and preserve framework invariants.

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
      opts.Token.Uri = "https://custom.example.com/token";
      opts.Response.TypesSupported = [ResponseType.Code];
      opts.Token.AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
  });
  ```

- **Add new validation rules for token endpoint client authentication** (per ADR 0002)
  - `Token.AuthMethodsSupported` must not be empty
  - `Token.AuthMethodsSupported` must contain at least one non-`None` method if `GrantTypesSupported` includes `ClientCredentials` (RFC 6749 §4.4 compliance)

[unreleased]: https://github.com/ChrisKlug/zeekayda-auth/compare/HEAD...HEAD
