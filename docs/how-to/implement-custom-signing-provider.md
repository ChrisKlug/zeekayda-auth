---
title: "Implement a custom signing key provider"
description: "How to build a custom rotating signing-key provider on the three-tier options hierarchy, using Azure Key Vault as the worked example."
parent: "How-to Guides"
nav_order: 13
---

*Added in Unreleased.*

<!--
  Outline stub — headings only. Content tracked as a follow-up to issue #409
  (ADR 0011 §3.4/§3.5 amendment). Fill in each section before publishing.
-->

## Before you start

## The three-tier options hierarchy

### `JwtSigningServiceOptions` — the shared base

### `StaticKeySourceOptions` — load-once providers

### `RotatingKeySourceOptions` — polling providers

## Choosing your tier

## Worked example: Azure Key Vault

### `KeyRotationCheckInterval` — the shared poll cadence

### `SigningKeyActivationDelay` — the Key-Vault-specific enforced invariant

### Where the invariant is enforced (and why in two places)

## Adapting the pattern to a custom KMS/HSM provider

## Common mistakes

## See also
