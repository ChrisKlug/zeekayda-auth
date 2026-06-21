---
name: post-merge-check
description: Verify if a merge requires changes to other issues etc
user-invocable: true
disable-model-invocation: true
allowed-tools:
  - dotnet *
---

# Post PR merge check

When a PR has been merged, and the remote branch deleted, the following should happen

---


## Steps

### 1. Delete the local branch

The merge has likely deleted the remote branch, so delete the local branch. And any worktree that might have been used

### 2. Pull the latest into the main branch

As the main branch has been updated, you need to pull the latest changes into the main branc. This should **always** be done, so you don't start new work on an old version of the code!

### 3. Verify if any blockers have changed

If this PR closes any issues, these issue might be set up as blockers for other issues. You need to make sure that these blocks are removed.

### Blocker Resolution on Merge

Whenever a PR is merged, automatically:

1. Note the merged PR number **and** any issue numbers it closes (e.g. `Closes #N` in the PR body).
2. Search all open draft PRs for a `## Blockers` section referencing the merged PR number or any closed issue number.
3. For each matching PR, remove that blocker entry from the PR body.
4. If the PR has no remaining blockers after removal, mark it as ready for review (`gh pr ready`).
5. For each closed issue, check whether it is a sub-issue of a `type:epic`. If so, query all sub-issues of that epic. If every sub-issue is now closed, ask the user whether to close the epic.
6. Use the GitHub CLI to look for any issue that has a blocker set up for any of the closed issues, and remove the blocks if found
