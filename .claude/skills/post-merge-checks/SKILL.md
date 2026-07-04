---
name: post-merge-checks
description: Housekeeping after a PR merges — delete the local branch, pull main, remove resolved blockers from draft PRs and issues, and check whether the parent epic can close. Run whenever a PR has been merged.
allowed-tools:
  - Bash(git *)
  - Bash(gh *)
---

# Post PR-Merge Checks

Run this whenever a PR has been merged. This skill is the single source of truth for the post-merge flow.

## Steps

### 1. Clean up local state

The merge has likely deleted the remote branch. Delete the local branch and any worktree that was used for it.

Then prune stale agent worktrees so they don't accumulate:

1. Run `git worktree prune`.
2. Run `git worktree list` and check every worktree under `.claude/worktrees/`:
   - If `git -C <path> status --porcelain` shows changes, leave it alone and report it to the user.
   - Otherwise, if its branch is merged into `main` (check with `git branch --merged main`) or its branch no longer has an open PR, remove it with `git worktree remove <path>` and delete the branch with `git branch -d <branch>`.
3. Report anything you left in place and why.

### 2. Update main

```sh
git checkout main
git pull --ff-only
```

**Always** do this so new work never starts from a stale main.

### 3. Resolve blockers

1. Note the merged PR number **and** any issue numbers it closes (e.g. `Closes #N` in the PR body).
2. Search all open draft PRs for a `## Blockers` section referencing the merged PR number or any closed issue number.
3. For each matching PR, remove that blocker entry from the PR body.
4. If a PR has no remaining blockers after removal, mark it ready for review (`gh pr ready`).
5. Issues use native blocked-by relations, which resolve automatically when the blocking issue closes — no cleanup needed. But check whether any issue just became fully unblocked (`gh api /repos/OWNER/REPO/issues/N/dependencies/blocked_by` on issues that listed a closed issue as a blocker) and report newly actionable issues to the user.

### 4. Check the parent epic

For each closed issue, check whether it is a sub-issue of a `type:epic`. If so, query all sub-issues of that epic. If every sub-issue is now closed, ask the user whether to close the epic.
