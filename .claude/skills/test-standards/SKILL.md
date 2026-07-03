---
name: test-standards
description: xUnit test conventions for ZeeKayDa.Auth — test categories, naming, structure, and tooling. Apply whenever writing, changing, or reviewing tests in this repository.
user-invocable: false
---

# Test Standards

These standards apply to **every test written in this repository**, regardless of which agent writes it.

## Test Categories

### Unit Tests (`tests/ZeeKayDa.Auth.Tests/`, `tests/ZeeKayDa.Auth.Analyzers.Tests/`, `tests/ZeeKayDa.Auth.AzureKeyVault.Tests/`)
- Test a single class or method in isolation
- No real HTTP, no real databases, no real time (use `TimeProvider` / clock abstractions)
- Fast: the entire unit test suite should run in < 10 seconds

### Integration Tests (`tests/ZeeKayDa.Auth.AspNetCore.Tests/`)
- Use `Microsoft.AspNetCore.Mvc.Testing` (`WebApplicationFactory`)
- Test full HTTP flows (authorization code flow, token exchange, etc.)
- Use in-memory storage
- Validate actual HTTP responses, headers, and cookies

### Security Tests (live within both suites)
- Prove that invalid redirect URIs are rejected
- Prove that PKCE enforcement cannot be bypassed
- Prove that expired tokens are rejected
- Prove that tampered tokens fail validation
- Prove that timing attacks are not possible on secret comparison

## Quality Standards

- Test method naming: readable English sentence style using underscores as word separators (e.g. `CreateConfidential_sets_IsPublic_to_false`, `Validate_returns_error_when_redirect_uri_is_missing`)
- One assertion concept per test (multiple `.Should()` chains on one result is fine; testing two different behaviours is not)
- Arrange/Act/Assert structure with blank lines separating sections
- Never use `Thread.Sleep` — use `ISystemClock` or `TimeProvider` abstractions
- Parameterised tests (`[Theory]` + `[InlineData]`) for boundary conditions and multiple invalid inputs
- Tests must be deterministic — no random data unless seeded and reproducible
- Every bug fix ships with a regression test that would have caught it

## Tooling

- **Test framework**: xUnit3
- **Assertions**: FluentAssertions
- **Mocking**: FakeItEasy
- **Web testing**: `Microsoft.AspNetCore.Mvc.Testing`
- **Benchmarking**: BenchmarkDotNet
- **Coverage**: `dotnet-coverage` / Coverlet — run `/check-code-coverage` before opening a PR
