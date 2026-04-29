# Replace HOMEBREW_TAP_TOKEN PAT with a GitHub App for cross-repo Homebrew tap publishing

Status: OPEN

Tracks #18. Stop using a calendar-expiring PAT for the `rebaze/homebrew-tap`
push during release. Mint a 1-hour GitHub App installation token at the start
of the release workflow and pass it to GoReleaser as `HOMEBREW_TAP_TOKEN`.

## Work in this repo

- Update `.github/workflows/release.yaml` to use
  `actions/create-github-app-token` and source `HOMEBREW_TAP_TOKEN` from
  `steps.app-token.outputs.token`.

## Out-of-repo work (manual, org admin)

- Create GitHub App `rebaze-release-bot` (Contents: r/w; Metadata: r;
  webhooks disabled; only this account).
- Install on `rebaze/scat` and `rebaze/homebrew-tap` with access scoped to
  those two repos.
- Add `RELEASE_APP_ID` (Actions variable) and `RELEASE_APP_PRIVATE_KEY`
  (Actions secret) to `rebaze/scat`.
- Delete the old `HOMEBREW_TAP_TOKEN` secret and revoke the underlying PAT.
- Recover the missed v0.6.0 cask via a hand-crafted PR against
  `rebaze/homebrew-tap` (issue #18, option (b)).

Close when the next tagged release produces a working
`brew install rebaze/tap/scat` end-to-end.
