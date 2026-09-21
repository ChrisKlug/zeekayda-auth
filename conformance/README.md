# Conformance testing

Runs the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) against
the [sample identity server](../samples/IdentityServer/README.md), which exists to be this suite's
target. Everything here is internal verification infrastructure — nothing in this folder ships in a
package.

`RESULTS.md` records what the suite found, and is rewritten by whoever runs it next.

## Run it

From the repository root:

```bash
./conformance/run-conformance.sh          # both plans
./conformance/run-conformance.sh config   # discovery and JWKS only, no browser
./conformance/run-conformance.sh basic    # the authorization code flow, 35 modules
```

Docker and the .NET SDK are the only prerequisites. The first run clones the suite into `suite/`
and pulls its images, which takes a few minutes; later runs reuse both. The images are shared by the
whole machine, but the clone (about 360 MB) is per checkout: with several worktrees, set
`ZEEKAYDA_CONFORMANCE_SUITE_DIR` to a folder outside all of them, and every checkout clones into it
once and reuses it. Only one run at a time per machine: the ports and the Compose project name are
fixed, so the script takes a lock at `/tmp/zeekayda-conformance.lock` and refuses to start while
another run holds it. Output lands in
`results/<timestamp>/`: the suite's own signed export zip, the run log, the identity server's log,
the suite server's log, and the discovery document as served.

A non-zero exit means the run produced a failure, warning or skip that the manifests in `expected/`
do not account for, or that an entry there did not occur. Those files are the gate — see below.

## What it sets up, and why

The suite's Java server runs in a container, a browser driving the suite runs on the machine, and
the issuer has to be one URL both agree on, because the suite checks that the issuer it configured
is the issuer that came back. So:

- The sample runs on **`https://zeekayda.localtest.me:5443`**. `localtest.me` is public DNS
  pointing at 127.0.0.1, so the machine resolves it with no hosts-file entry and no sudo, and
  `docker-compose.override.yml` maps the same name to `host-gateway` inside the suite's container.
  Kestrel binds `*:5443` rather than that hostname — the suite reaches this machine over the Docker
  bridge, which is not an address the name resolves to.
- `make-certs.sh` generates a throwaway CA and server certificate into `certs/` (gitignored), and
  `Dockerfile.suite-server` bakes the CA into the suite image's JDK trust store. The ASP.NET
  development certificate will not do: the Java server has no reason to trust it.
- `Dockerfile.runner` runs the suite's own `scripts/run-test-plan.py`, so a run needs nothing on the
  machine but Docker — no Python, no pip install.
- Login is driven by the suite, through the `browser` block in `config/zeekayda.json`: the sample's
  login page has stable ids (`username`, `password`, `login-submit`), and the conformance clients
  are registered with `RequireConsent` false, so there is no consent page to script. Deleting that
  block makes the same config run interactively, for confirming a suspicious failure by hand.
- Four modules hold an image placeholder a human certifier would fill with a screenshot: the two
  that ask for a second login and the two that must end on the server's own error page. The
  `override` block in the same file gives each of those modules a browser script whose `wait`
  command carries `update-image-placeholder`, which captures the page into the placeholder. Without
  it the module sits in `WAITING` until the runner gives up after 240 s. Such a module finishes as
  `REVIEW`, which the runner treats as a pass.
- The conformance clients are registered with `RequirePkce` set to `false`. The basic plan's
  modules send no `code_challenge`, and the suite has no way to make them send PKCE, so without the
  OAuth 2.1 §7.5.1.1 opt-out every module is refused at the authorization endpoint.
- Three clients are registered, not two. `oidcc-server-client-secret-post` copies the config's
  top-level `client_secret_post` block over `client` before it runs, so that block needs only an id
  and a secret — it names `conformance-client-post`, which the sample registers with
  `client_secret_post` as its only permitted token endpoint authentication method. A separate client
  rather than a second method on `conformance-client` keeps the other modules exercising
  `client_secret_basic` and nothing else, which is how the suite's own comment says most servers are
  set up. `client_secret_post` is advertised server-wide in the sample, so it appears in the
  discovery document of every environment, not only this one.

The suite's scripts and its published images have to agree, so `SUITE_REF` in `run-conformance.sh`
pins both to one release. Moving to a newer suite is a deliberate edit there, with a re-run.

## The expected-results manifests

`expected/` holds one failures file per plan (`config.failures.json`, `basic.failures.json`)
listing the failures and warnings that plan is allowed to produce, and `basic.skips.json` listing
the modules allowed to skip. They are the suite's own format, and the runner takes them with
`--expected-failures-file` and `--expected-skips-file`. They are split per plan because the runner
also fails a run in which an expected entry never occurred, so one shared file would make a
single-plan run fail on the other plan's entries.

```json
{
    "test-name": "oidcc-discovery-endpoint-verification",
    "variant": { "server_metadata": "discovery", "client_registration": "static_client" },
    "configuration-filename": "*zeekayda.json",
    "current-block": "",
    "condition": "OIDCCCheckDiscEndpointClaimsSupported",
    "expected-result": "warning",
    "comment": "why this is tolerated, and the issue that will remove it"
}
```

A skip entry has the same shape minus `current-block`, `condition` and `expected-result`.

Every entry names the issue that deletes it, or the register decision that makes it permanent. An
entry with neither is a gap nobody has agreed to live with. Run with `--verbose` (the script always
does) and the runner prints a ready-made entry for anything unexpected it hits, which is the fastest
way to add one honestly.

## In CI

The `conformance` job in `.github/workflows/ci.yml` runs `run-conformance.sh all` on every pull
request and every push to `main`, and joins the `ci-complete` aggregate, so a run that trips the
manifests blocks the merge. The results tree is uploaded as the `conformance-results` artifact
whether the run passed or failed.

**Why every PR rather than nightly.** Measured on a developer machine with the images and the
suite clone already present, both plans together take **2 min 11 s** wall clock end to end — suite
boot to teardown. The config plan alone is 46 s, almost all of it fixed cost: waiting for the Java
server, building and starting the sample, teardown. The basic plan's 35 modules add about 90 s, a
third of which is one module's deliberate 30 s wait before replaying a code. The full breakdown is
in `RESULTS.md`. Two and a bit minutes is cheap enough for every PR, and the login flow is exactly
the kind of thing a PR breaks by accident; a nightly-only basic plan would find that a day late.

CI caches the suite clone by `SUITE_REF`, which the job reads out of `run-conformance.sh` rather
than repeating. **The suite's images are deliberately not cached.** Measured on the runner, a job
with the clone cached takes the same 3 min 05 s as one without it, and breaks down as:

| Phase | Time |
|---|---:|
| job setup, checkout, .NET, cache restore | 8 s |
| pull nginx and mongo, build the suite-server image | 19 s |
| suite boots until it answers | 12 s |
| sample builds and starts until discovery answers | 39 s |
| both plans | 93 s |
| teardown | 11 s |

The images are 19 s of that. Caching them means `docker save`/`docker load` of roughly 600-700 MB,
which is not obviously faster than the pull, costs that much again on every miss, and competes for
the repository's 10 GB Actions cache with the NuGet caches every other job depends on. If this job
ever needs to be faster, the two rows worth attacking are the sample's 39 s — it is built serially
after the suite is already up, and could be built while the suite boots — and the plans' 93 s, of
which about 31 s is `oidcc-codereuse-30seconds` deliberately sleeping and therefore fixed.
