---
name: review-branch
description: Set up a git worktree for reviewing or auditing a branch or PR so the review runs against the right code. Use before any code review, audit, or acceptance-criteria verification that targets a branch other than the currently checked-out one.
argument-hint: [branch or PR number]
allowed-tools:
  - Bash(git *)
  - Bash(gh *)
---

# Review a Branch or PR

Reviewing a stale or unrelated branch produces false negatives — changes that are already implemented appear missing. Always confirm the right branch first.

## Steps

### 1. Identify the target branch

The branch containing the changes may be `main`, a feature branch, or a PR branch. Do **not** assume the currently checked-out branch is correct. If a PR number was given, resolve it: `gh pr view <N> --json headRefName`. If the target is unclear, ask which branch/PR to review before proceeding.

### 2. Create a worktree for it

```sh
git fetch origin
git worktree add ../review-<branch-or-pr> <branch>
```

### 3. Do all review work inside the worktree

Read, build, and test against the worktree path — never against the main checkout.

### 4. Remove the worktree when done

```sh
git worktree remove ../review-<branch-or-pr>
```
