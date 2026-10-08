# Maintaining the shared repositories

Development uses the clean `main` branch. `github` is the GitHub remote and
`origin` is the Gitea remote. The local `codex/gitea-integration` branch preserves
Gitea's older history and receives `main` commits in one direction only.
The initial integration joined equal trees with `--allow-unrelated-histories`;
normal subsequent updates do not need that option.

## Prepare a change

```powershell
git switch main
git config --local user.name Moritz
git config --local user.email 6755265+Netfreak25@users.noreply.github.com
git status --short
```

Make a focused change, run the affected checks, stage named files and review
`git diff --cached`. Check new files for private data before committing.
Do not add the entire workspace or copy private attachments into source archives.
Keep `.gitignore` exclusions for local data and generated artifacts.

## Verify history and prepare Gitea locally

The preserved `codex/standalone` branch is the old-history baseline. It must never
be an ancestor of the clean development branch. The following command must
return exit code **1** (not an error code greater than 1):

```powershell
git merge-base --is-ancestor codex/standalone main
```

Then integrate only in this direction:

```powershell
git switch codex/gitea-integration
git merge --no-ff main
git diff --exit-code main codex/gitea-integration
git rev-parse 'main^{tree}' 'codex/gitea-integration^{tree}'
git switch main
```

Require identical tree IDs and no diff. Resolve any conflict locally before
publication; do not merge the integration branch back into `main`. Preserve the
single root of `main` (`git rev-list --max-parents=0 main`) and do not merge
foreign history. Gitea's existing remote commits, tags and releases stay intact.

## Build a release

Follow [BUILD.md](BUILD.md), build all three distributions, and run the full
[memory suite](MEMORY-TEST-SUITE.md). Retain the build receipts locally.
Review the exact committed tree, licenses and documentation links. Tag the
canonical `main` commit only after checks pass. Create one set of release FAPs
and SHA256SUMS; retain those exact artifacts for either platform.

## Publish only when authorized

Push and release are separate permissions for each platform. The commands below
are examples, not standing authorization. Replace `<tag>` with the single
approved tag. Do not use `--all`, `--tags`, `--mirror` or force options.

For GitHub:

```powershell
git -c push.followTags=false push github main:refs/heads/main
git -c push.followTags=false push github refs/tags/<tag>
```

For Gitea, first fetch its current branch and require that it is an ancestor of
the prepared integration branch. Unexpected remote changes require review.

```powershell
git fetch origin main
git merge-base --is-ancestor origin/main codex/gitea-integration
git -c push.followTags=false push origin codex/gitea-integration:refs/heads/main
git -c push.followTags=false push origin refs/tags/<tag>
```

Only run the push after the ancestor check returns 0. A Gitea tag points to the
same canonical development commit as its GitHub counterpart; the integration
branch additionally retains the old history.

For each authorized release, create a draft, attach the three FAPs and
SHA256SUMS, download them and compare hashes, then publish as a prerelease until
hardware acceptance. Verify the public downloads and README links afterward.
The same release name must have the same source and FAP hashes on both hosts.
Never silently overwrite existing release assets. No automatic synchronization
or CI publication is configured.
