# TB2 Manager project rules

## Scope and development

- Develop the shared source on `main`, whose history starts with the clean public baseline.
- `github` targets GitHub; `origin` targets Gitea. Keep the existing Gitea history.
- `codex/gitea-integration` carries the old history and receives merges from `main` only. Never merge that branch, old tags, or Gitea history into `main`.
- Both platforms use the same code. Do not maintain platform-specific feature variants.
- The separate Core Flasher Flipper App is outside this project's scope.
- Preserve existing behavior and memory limits. Make focused changes and local commits after appropriate verification.

## Publication

- Push and release require explicit authorization for each named platform and each action. Ask for the target when a publication request is ambiguous.
- A GitHub authorization does not authorize Gitea publication, or vice versa. Builds and commits never publish automatically.
- Use explicit branches and individual tags. No force push, mirror push, all-branch or all-tag publication.
- Before publication, prove that `main` has no old Gitea ancestors and that the Gitea integration tree equals the corresponding `main` tree.
- An identical release designation on both platforms means the same development source and identical FAP SHA-256 values. Keep the canonical release artifacts; do not silently replace an existing release or attachment.
- Do not update an SD card without explicit authorization.
- Follow [the maintenance procedure](docs/MAINTENANCE.md).

## Privacy and attribution

- Audit the Git index, including every new file, before publishing. Publish tracked source, never a copy of the whole workspace.
- Exclude credentials, private attachments, machine configuration, personal local paths, logs, SDKs, generated builds, images, box records and device-derived test data.
- Keep licenses, third-party provenance and required upstream authors intact.
- New project commits use `Moritz <6755265+Netfreak25@users.noreply.github.com>` through repository-local Git configuration. Do not rewrite existing Gitea authors.

## Verification

- For code changes run the directly affected tests, linter and memory regression suite. Rebuild affected targets when build inputs change; stale artifacts are not evidence.
- Before releases build Unleashed, Momentum and Official; require host regressions, lint, APPCHK, loader, stack and memory checks. Verify ten embedded modules and no bundled device firmware.
- Use the pinned SDKs and unchanged limits documented in [BUILD](docs/BUILD.md) and [the memory suite](docs/MEMORY-TEST-SUITE.md).
- Investigate failed checks before further changes. Do not claim a fix without a reproducer and appropriate regression evidence.
- Artifact checks do not replace hardware tests. Until device acceptance, call FAPs **unverified build candidates**.
