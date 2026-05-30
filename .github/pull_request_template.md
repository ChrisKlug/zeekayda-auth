## Summary

<!-- One or two sentences describing what this PR does and why. -->

Closes #<!-- issue number -->

---

## Type of Change

<!-- Check all that apply -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behaviour to change)
- [ ] Refactor (no behaviour change)
- [ ] Documentation only
- [ ] CI / tooling / chore

---

## Checklist

### Required for all PRs

- [ ] PR title follows Conventional Commits format (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`, `security:`)
- [ ] All commits are signed off with `git commit -s` (DCO — see [CONTRIBUTING.md](../CONTRIBUTING.md#developer-certificate-of-origin-dco))
- [ ] CI passes (build, tests, lint)

### Code changes

- [ ] Tests added or updated to cover the change
- [ ] Existing tests still pass
- [ ] XML doc comments added on all new public types and members
- [ ] No `TODO` comments left in merged code (open an issue instead)

### Documentation

- [ ] User-facing documentation updated (required for any public API or behaviour change)
- [ ] CHANGELOG.md updated under `[Unreleased]`

### Security

- [ ] The security agent has been tagged for review (`@security`) if this PR touches any of the following:
  - Token issuance, validation, or signing
  - Cryptographic operations or key management
  - OAuth 2.0 / OpenID Connect endpoints or flows
  - Client authentication or secret handling
  - Session management or cookie handling

---

## Security Agent Sign-off

<!-- 
  If this PR touches tokens, cryptography, endpoints, or auth flows:
  Tag @ChrisKlug and note "security review required".
  The PR cannot be merged without security sign-off on protocol-level changes.
-->

- [ ] Not required (this PR does not touch security-sensitive code)
- [ ] Required — security review requested (tag the security agent)

---

## Testing Notes

<!-- Describe how you tested this change. What scenarios did you verify? -->

---

## Screenshots / HTTP Traces (if applicable)

<!-- Redact any tokens, secrets, or PII before pasting. -->
