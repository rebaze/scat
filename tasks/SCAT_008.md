# Robust SBOM detection for files larger than 64 KiB

Status: CLOSED

## Summary

`DetectInputKind` in `internal/scan/ingest.go` previously read only the first
64 KiB of a regular file and tried to `json.Unmarshal` that head as a complete
JSON document. Any real-world CycloneDX SBOM exceeds 64 KiB, so the parse
failed with a syntax error, the sniff was skipped, and the function fell
through to `InputPURLList`. The downstream PURL flow then complained about
unparseable lines, which obscured the real cause.

## Fix

- Switch detection to a streaming `json.Decoder`. The decoder walks top-level
  keys until it finds `bomFormat` (→ CycloneDX) or `spdxVersion` (→ SPDX),
  skipping past any preceding values regardless of size.
- When a file is JSON-shaped (starts with `{` after whitespace) but has neither
  key, return an explicit error instead of silently falling through to the PURL
  path. JSON arrays (`[`) similarly get a clear error.
- PURL fallback now applies only when the file does not begin with `{` or `[`.

## Tests

Added regression tests in `internal/scan/ingest_test.go`:

- `TestDetectInputKindLargeCycloneDX` — fixture comfortably > 64 KiB.
- `TestDetectInputKindCycloneDXWithBOMFormatLate` — `bomFormat` after a large
  `components` array.
- `TestDetectInputKindUnknownJSON` — expects explicit error.
- `TestDetectInputKindJSONArray` — expects explicit error.
- `TestDetectInputKindCycloneDXWrongFormat` — bomFormat=SWID rejected.
- `TestDetectInputKindLeadingWhitespace` — whitespace before `{` is ignored.
