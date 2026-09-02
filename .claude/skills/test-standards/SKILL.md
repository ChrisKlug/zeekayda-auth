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

## When a test is NOT wanted

Tests are written for behaviour that can plausibly break, or to record a security decision —
**never to reach a coverage number**. The coverage gate tolerates deliberately leaving obvious
code untested; do not write a test whose only function is to satisfy it.

On **non-security** types, the following are explicitly not wanted:

- Guard-clause tests (`ArgumentNullException` / throws-on-null assertions)
- DI-resolution assertions ("service X resolves from the container")
- `ToString` tests
- Trivial property round-trips and "constructor sets property" tests
- Any test locking behaviour you just *know* works — if it cannot meaningfully break, it is
  dead weight

**Security-surface carve-out:** `docs/decisions/security-sign-offs.md` cites tests as proof of
closed threats — by method name, by class name, or by wildcard. Any test a citation covers is the
durable record of the decision and stays regardless of which category it falls into; renaming one
breaks its citation, so the register is re-checked on rename. Security surfaces include tokens,
crypto, endpoints, storage, **startup verification and configuration-failure aggregation, and the
registration of any security control or its warning service**. On those surfaces the rule is
binding, not advisory: keep every test whose failure would let a control fail open or go
unregistered — a "does AddX register the control?" test is control-presence, not a DI-resolution
assertion, even though it looks like one.

When in doubt, keep the test.

## Acting on a mutation report

A Stryker result is a lead, not evidence. **Before writing a test for a survivor, and before
claiming one is killed, make the mutation by hand and run the suite** — edit the source as the
report describes, confirm the tests fail (or don't), restore. The tool's status has been wrong in
both directions in this repository:

- **A reported survivor may already be covered.** Two `_ => false` arms guarding a certificate
  secret/`Cer` self-test were reported survived; two existing tests kill them, one an integration
  test. Writing tests for those would have been a day spent duplicating tests that existed.
- **A reported kill may be a test that proves nothing.** Asserting `ArgumentNullException` with a
  parameter name is worthless if the call downstream raises the same type with the same name — the
  test passes with the guard deleted, and the report calls the mutant killed.

**An equivalent mutant is not a coverage gap.** A mutation that cannot change observable behaviour
has no test that can close it: a `First()` after a non-empty guard, a `>` where both branches return
the same value on a tie, a `TryAdd` the caller already performed. Say so in the PR and move on.
Contorting a test to chase one produces a test that asserts nothing, and its uncoverable branch then
survives every future run.

**A mutation report does not override the section above.** Guard-clause and DI-resolution mutants on
a non-security type stay unkilled and are justified in the PR; closing them is not a reason to write
a test this repository does not want. On a security surface — a signer, a key source, the
registration of a security control — those same tests are wanted, and the carve-out is why.

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
