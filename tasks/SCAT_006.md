# Accept pre-existing CycloneDX SBOM as input

Status: OPEN

## Summary

Allow `scat <path>` to accept a CycloneDX JSON SBOM directly, in addition to the existing folder (Syft-generated) and PURL-list inputs.

## Motivation

The downstream pipeline (Grype vuln scan, license check, reporting) is already SBOM-file-driven — it reads `<prefix>-sbom.json` from disk. Today the CLI dispatch in `cmd/root.go` routes any regular file to `CreateSBOMFromPURLs`, which rejects non-`pkg:` lines. There is no architectural blocker; only the input-detection step is missing.

## Scope

- Detect input kind by JSON-sniffing: directory → Syft, CycloneDX SBOM → ingest, otherwise → PURL list.
- Reject SPDX with a clear error (license extraction is CycloneDX-shaped — SPDX support is a follow-up).
- Strip a trailing `-sbom` from the prefix so report files are named `<name>-summary.html`, not `<name>-sbom-summary.html`.
- Keep existing folder and PURL flows unchanged.

## Implementation Notes

- New `internal/scan/ingest.go` with `DetectInputKind(path) (InputKind, error)` and `IngestSBOM(srcPath, outPath string) error`.
- `IngestSBOM` validates `bomFormat == "CycloneDX"` and copies the file to `outPath`. The cleanup at the end of `runAnalyze` (`os.Remove(sbomPath)`) must be skipped when the user provided the SBOM.
- Tests live in `internal/scan/ingest_test.go`.
