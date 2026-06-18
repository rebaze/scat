# Migrate release attestations to Node 24 action

Status: OPEN

## Summary

Update the release workflow to use `actions/attest@v4.1.0` directly for build
provenance and SBOM attestations.

## Motivation

The `v0.8.1` release completed successfully, but GitHub Actions emitted Node.js
20 deprecation warnings for the attestation actions. GitHub will force Node.js
24 by default on June 2, 2026 and remove Node.js 20 from hosted runners on
September 16, 2026. Migrating now keeps the release workflow warning-free and
avoids a later forced runtime change.

## Scope

- Replace `actions/attest-build-provenance@v2.4.0` with pinned
  `actions/attest@v4.1.0`.
- Replace `actions/attest-sbom@v2.4.0` with pinned `actions/attest@v4.1.0`.
- Preserve the existing release attestation verification gate.
- Keep release action dependencies pinned by commit SHA.

## Verification

- Normal PR CI passes.
- The next release candidate confirms the release workflow no longer emits the
  Node.js 20 attestation warning.
- `gh attestation verify` continues to pass for provenance and CycloneDX SBOM
  attestations.

## Out of scope

- Changing the release artifact set.
- Changing signing, checksums, or Homebrew tap publication behavior.
