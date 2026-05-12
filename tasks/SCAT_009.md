# Sigstore + SLSA Build L3 for releases

Status: OPEN

## Summary

Bring the scat release pipeline up to SLSA v1.0 Build Level 3 by signing and
attesting every release artifact via Sigstore through GitHub Artifact
Attestations. Producer side only — scat itself does not yet verify sigstore
signatures on inputs (separate future task).

## Motivation

We ship an SCA tool. Our own release artifacts should pass the same supply-chain
checks our reports recommend to customers. Today releases are unsigned, have no
SBOM, and offer no build provenance.

## Scope

- Build provenance attestation (`actions/attest-build-provenance@v2`) over every
  release archive (`*.tar.gz`, `*.zip`) and `checksums.txt`.
- One CycloneDX source SBOM per release, attached to the GitHub release and
  attested via `actions/attest-sbom@v2`.
- `id-token: write` + `attestations: write` permissions added to the release
  job; GitHub OIDC → Fulcio → Rekor handled transparently.
- Homebrew tap (`rebaze/homebrew-tap`) update gated on attestation
  verification: split into a second job (`publish-tap`) that depends on a
  successful attestation verify gate in the `release` job.
- README "Verifying releases" section documenting `gh attestation verify` and
  `cosign verify-attestation` flows.

## Files touched

- `.github/workflows/release.yaml` — split into `release` + `publish-tap` jobs;
  added Syft install, attestations, verification gate, dist artifact upload,
  cask update script.
- `README.md` — added "Verifying releases" section under Install.
- `tasks/SCAT_009.md` — this file.

## Verification

Headline tests:

1. Push a pre-release tag (e.g. `v0.0.0-rc1`); confirm the `release` job runs
   end-to-end (build + attest + verify gate green) and the `publish-tap` job is
   **skipped** by design — pre-release tags must not touch the production
   Homebrew tap. `gh attestation list --repo rebaze/scat` should show entries.
2. Cut a real (non-pre-release) tag; confirm `publish-tap` runs and bumps the
   cask in `rebaze/homebrew-tap`.
3. Negative test: temporarily break the verify step on a throwaway tag and
   confirm `publish-tap` does NOT run.
4. From a clean machine: `gh release download` then
   `gh attestation verify` and `cosign verify-attestation` — both must succeed.

Close this task once a real tagged release ships with all checks green.

## Out of scope

- Adding sigstore verification capabilities to the scat CLI itself.
- `slsa-framework/slsa-github-generator` migration (Artifact Attestations
  already provide SLSA v1.0 Build L3).
- Container image signing (no images published).
- Reproducible builds.
