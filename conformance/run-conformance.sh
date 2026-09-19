#!/usr/bin/env bash
#
# Runs the OpenID Foundation conformance suite against the sample identity server.
#
#   ./run-conformance.sh [config|basic|all]
#
# Boots the suite (MongoDB, nginx, the Java server) and the sample identity server, runs the
# requested test plan headlessly, writes the results under results/, and tears everything down.
# Docker and the .NET SDK are the only prerequisites.
#
# Issue #306 produced this script; #307 turns it into a CI workflow.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
SUITE_DIR="${HERE}/suite"

# The suite's scripts and its published images have to agree, so both are pinned to one release and
# moved together. A newer suite is a deliberate change, made here, with a re-run to prove it.
SUITE_REF="${SUITE_REF:-release-v5.3.1}"
export IMAGE_TAG="${IMAGE_TAG:-${SUITE_REF}}"

# Fixed, not overridable. The name also appears literally in the sample's issuer
# (samples/IdentityServer/appsettings.Conformance.json) and in the browser-match strings
# (config/zeekayda.json), which no environment variable can reach, so an override here would
# change the certificate and the container's host mapping while the issuer stayed behind — a
# broken run wearing the look of a supported knob. Changing the hostname means editing those two
# files, docker-compose.override.yml and make-certs.sh alongside this line.
OP_HOST=zeekayda.localtest.me
OP_BASE="https://${OP_HOST}:5443"
DISCOVERY_URL="${OP_BASE}/.well-known/openid-configuration"
SUITE_URL="https://localhost.emobix.co.uk:8443"

WHICH="${1:-all}"
case "${WHICH}" in
    config|basic|all) ;;
    *) echo "usage: $(basename "$0") [config|basic|all]" >&2; exit 2 ;;
esac

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULT_DIR="${HERE}/results/${RUN_STAMP}"
mkdir -p "${RESULT_DIR}"

compose() {
    docker compose \
        --project-directory "${SUITE_DIR}" \
        --project-name zeekayda-conformance \
        -f "${SUITE_DIR}/docker-compose-prebuilt.yml" \
        -f "${HERE}/docker-compose.override.yml" \
        "$@"
}

OP_PID=""
cleanup() {
    local status=$?
    echo
    echo "==> tearing down"
    if [[ -n "${OP_PID}" ]] && kill -0 "${OP_PID}" 2>/dev/null; then
        kill "${OP_PID}" 2>/dev/null || true
        wait "${OP_PID}" 2>/dev/null || true
    fi
    compose logs --no-color server > "${RESULT_DIR}/suite-server.log" 2>&1 || true
    compose down --remove-orphans >/dev/null 2>&1 || true
    echo "==> results in ${RESULT_DIR}"
    exit "${status}"
}
# Cleanup hangs off EXIT alone. Trapping INT and TERM on it too would run cleanup with $? set by
# whatever command happened to finish last — usually 0 — so a cancelled run tore everything down
# and then reported success. These two turn the signal into the conventional exit status first,
# and the EXIT trap then carries that status out.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- the suite's source, for its scripts and compose file -----------------------------------------
if [[ ! -d "${SUITE_DIR}/.git" ]]; then
    echo "==> cloning the conformance suite at ${SUITE_REF}"
    git clone --depth 1 --branch "${SUITE_REF}" \
        https://gitlab.com/openid/conformance-suite.git "${SUITE_DIR}"
fi

# An existing clone is only reusable if it is the ref the images are tagged from. Reusing whatever
# was cloned first, while IMAGE_TAG follows a newly-set SUITE_REF, would run one release's scripts
# against another release's server image — the exact mismatch pinning both to SUITE_REF exists to
# prevent, and one that would look like a conformance failure rather than a setup error.
WANTED_REF="$(git -C "${SUITE_DIR}" rev-parse --verify --quiet "refs/tags/${SUITE_REF}" || true)"
if [[ -z "${WANTED_REF}" || "$(git -C "${SUITE_DIR}" rev-parse HEAD)" != "${WANTED_REF}" ]]; then
    echo "==> moving the suite clone to ${SUITE_REF}"
    git -C "${SUITE_DIR}" fetch --depth 1 --force origin \
        "refs/tags/${SUITE_REF}:refs/tags/${SUITE_REF}"
    git -C "${SUITE_DIR}" checkout -q --detach "refs/tags/${SUITE_REF}"
fi
echo "==> suite at ${SUITE_REF} ($(git -C "${SUITE_DIR}" rev-parse --short HEAD))"

# --- TLS the Java server will accept --------------------------------------------------------------
"${HERE}/make-certs.sh"

# --- the suite ------------------------------------------------------------------------------------
echo "==> starting the conformance suite"
compose up -d --build mongodb server nginx

echo -n "==> waiting for the suite to answer"
for _ in $(seq 1 120); do
    if curl -ksf "${SUITE_URL}/api/runner/available" >/dev/null 2>&1; then
        echo " ok"
        break
    fi
    echo -n "."
    sleep 2
done
if ! curl -ksf "${SUITE_URL}/api/runner/available" >/dev/null 2>&1; then
    echo " timed out"
    echo "The suite did not come up. Its log is being written to ${RESULT_DIR}/suite-server.log" >&2
    exit 1
fi

# --- the sample identity server -------------------------------------------------------------------
echo "==> starting the sample identity server on ${OP_BASE}"
dotnet run --project "${REPO_ROOT}/samples/IdentityServer" --launch-profile Conformance \
    > "${RESULT_DIR}/identity-server.log" 2>&1 &
OP_PID=$!

echo -n "==> waiting for discovery"
for _ in $(seq 1 90); do
    if curl -sf --cacert "${HERE}/certs/ca.pem" "${DISCOVERY_URL}" >/dev/null 2>&1; then
        echo " ok"
        break
    fi
    if ! kill -0 "${OP_PID}" 2>/dev/null; then
        echo " the identity server exited"
        tail -30 "${RESULT_DIR}/identity-server.log" >&2
        exit 1
    fi
    echo -n "."
    sleep 2
done
if ! curl -sf --cacert "${HERE}/certs/ca.pem" "${DISCOVERY_URL}" >/dev/null 2>&1; then
    echo " timed out"
    tail -30 "${RESULT_DIR}/identity-server.log" >&2
    exit 1
fi
curl -s --cacert "${HERE}/certs/ca.pem" "${DISCOVERY_URL}" > "${RESULT_DIR}/discovery.json"

# --- the plans ------------------------------------------------------------------------------------
# static_client: the framework has no dynamic client registration, so the suite uses the two clients
# registered in appsettings.Conformance.json. discovery: metadata is read from the discovery
# document rather than configured by hand. The config plan fixes
# both variants itself and rejects the plan outright if either is passed again, so only the basic
# plan names them.
CONFIG="/conformance/config/zeekayda.json"
PLANS=()
[[ "${WHICH}" == "config" || "${WHICH}" == "all" ]] && \
    PLANS+=( "oidcc-config-certification-test-plan" "${CONFIG}" )
[[ "${WHICH}" == "basic"  || "${WHICH}" == "all" ]] && \
    PLANS+=( "oidcc-basic-certification-test-plan[client_registration=static_client][server_metadata=discovery]" "${CONFIG}" )

echo "==> running: ${WHICH}"
set +e
compose run --rm --build runner \
    --expected-failures-file /conformance/expected-failures.json \
    --export-dir "/conformance/results/${RUN_STAMP}" \
    --verbose \
    "${PLANS[@]}" \
    2>&1 | tee "${RESULT_DIR}/run.log"
RUN_STATUS="${PIPESTATUS[0]}"
set -e

echo
if [[ "${RUN_STATUS}" -eq 0 ]]; then
    echo "==> plan finished with no unexpected failures"
else
    echo "==> plan finished with unexpected failures or warnings (exit ${RUN_STATUS}); see run.log"
fi
exit "${RUN_STATUS}"
