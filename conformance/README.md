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
and pulls its images, which takes a few minutes; later runs reuse both. Output lands in
`results/<timestamp>/`: the suite's own signed export zip, the run log, the identity server's log,
the suite server's log, and the discovery document as served.

A non-zero exit means the run produced a failure or warning that `expected-failures.json` does not
account for. That file is the gate — see below.

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

The suite's scripts and its published images have to agree, so `SUITE_REF` in `run-conformance.sh`
pins both to one release. Moving to a newer suite is a deliberate edit there, with a re-run.

## The expected-results manifest

`expected-failures.json` lists the failures and warnings a run is allowed to produce. It is the
suite's own format, and the runner takes it with `--expected-failures-file`:

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

Every entry names the issue that deletes it. An entry without one is a gap nobody has agreed to
live with. Run with `--verbose` (the script always does) and the runner prints a ready-made entry
for anything unexpected it hits, which is the fastest way to add one honestly.

## Running it in CI (#307)

**Recommendation: the config plan on every PR, the basic plan nightly once #708 lands.**

Measured on a developer machine with images and the suite clone already present, both plans
together take **42.5 s** wall clock end to end — suite boot to teardown. Of that, roughly 25 s is
waiting for the Java server to answer and about 1 s is the config plan's single module. That is
cheap enough to put on every PR, and the discovery document is exactly the kind of thing a PR
breaks by accident.

The 42.5 s is **not** evidence for what a working basic plan costs: all 35 of its modules currently
abort during setup within a second (see `RESULTS.md`), so the figure measures a plan that does no
work. Time it again before deciding where the basic plan belongs. Nightly is the safe assumption —
35 browser-driven modules, run serially because the config carries an `alias`.

A first CI run must budget for the cold path the measurement excludes: cloning the suite and
pulling its two images. Cache both by `SUITE_REF`.
