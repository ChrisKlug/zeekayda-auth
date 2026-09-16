---
name: post-merge-checks
description: Housekeeping after a PR merges — delete the local branch, pull main, remove resolved blockers from draft PRs and issues, and check whether the parent epic can close. Run whenever a PR has been merged.
allowed-tools:
  - Bash(git *)
  - Bash(gh *)
  - Agent
---

# Post PR-Merge Checks

Run this whenever a PR has been merged. This skill is the single source of truth for the post-merge flow.

Steps 1 and 2 mutate the local working tree the main session is sitting in, so the **main session runs
them itself** — never from a subagent. A `git -C` cwd reset from a subagent renamed `refs/heads/main`
here once, and the two steps are a handful of commands, so there is nothing to gain by moving them.

Steps 3 and 4 are read-mostly GitHub queries with no local state and no design context, and they are
where most of the turns go. The main session **delegates them to the `housekeeper` agent**
(foreground), passing the merged PR number and the issue numbers it closed, and acts on the report
that comes back. The agent cannot ask you anything — anything needing a decision comes back as a
question in its result, and the main session puts it to the user.

## Steps

### 1. Clean up local state — main session only

The merge has likely deleted the remote branch. Delete the local branch and any worktree that was used for it.

Then prune stale agent worktrees so they don't accumulate:

1. Run `git worktree prune`.
2. Run `git worktree list` and check every worktree under `.claude/worktrees/`:
   - If `git -C <path> status --porcelain` shows changes, leave it alone and report it to the user.
   - Otherwise, if its branch is merged into `main` (check with `git branch --merged main`) or its branch no longer has an open PR, remove it with `git worktree remove <path>` and delete the branch with `git branch -d <branch>`.
3. Report anything you left in place and why.

### 2. Update main — main session only

```sh
git checkout main
git pull --ff-only
```

**Always** do this so new work never starts from a stale main.

### 3. Resolve blockers — `housekeeper` agent

1. Note the merged PR number **and** any issue numbers it closes (e.g. `Closes #N` in the PR body).
2. Search all open draft PRs for a `## Blockers` section referencing the merged PR number or any closed issue number.
3. For each matching PR, remove that blocker entry from the PR body.
4. If a PR has no remaining blockers after removal, mark it ready for review (`gh pr ready`).
5. Issues use native blocked-by relations, which resolve automatically when the blocking issue closes — no cleanup needed. But check whether any issue just became fully unblocked (`gh api /repos/OWNER/REPO/issues/N/dependencies/blocked_by` on issues that listed a closed issue as a blocker) and report newly actionable issues to the user.

### 4. Check the parent epic — `housekeeper` agent

For each closed issue, check whether it is a sub-issue of a `type:epic`. If so, query all sub-issues of that epic. If every sub-issue is now closed, **report the epic number and its sub-issue list as a question in your result** — never close it yourself. The main session asks the user whether to close it.
