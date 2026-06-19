---
name: check-formatting
description: Run dotnet format to verify that the code has been formatted properly
user-invocable: true
disable-model-invocation: true
allowed-tools:
  - dotnet *
---

# Run dotnet format

This skill finds the solution file in the root and runs format on it. If it comes back with errors, it should fix them, and re-run `dotnet format`until there are no more errors

---


## Steps

### 1. Find the solution file

Run:

```sh
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
```

To find the repo root

### 2. Move to repo root

Run:

```sh
cd "$REPO_ROOT"
```

To make the repo root the current working directory

### 3. Run format

Run:

```sh
if OUTPUT=$(dotnet format --verify-no-changes 2>&1); then
  exit 0
fi

REASON=$(printf 'Formatting check failed. Run `dotnet format` to fix the issues before finishing.\n\nOutput:\n%s' "$OUTPUT" | head -c 4000)
jq -cn --arg reason "$REASON" '{"decision":"block","reason":$reason}'
```

To see if there are any formatting issues

### 4. If formatting does not return 0

Run:

```sh
dotnet format
```

to format the code. 

Then start over at step 1 again until there are no more errors
