#!/usr/bin/env bash
# test-swagger-gaps.sh
#
# Compares harbor-cli main vs feature branch output for three API edge cases
# that are missing from the swagger spec on main but fixed on the feature branch:
#
#   1. DELETE repository with immutable-tagged image  → 412
#   2. GET list endpoint with oversized page-size     → 422
#   3. PUT /system/configurations with bad values     → 400 / 422
#
# Prerequisites:
#   - A running Harbor instance reachable at HARBOR_HOST
#   - Admin credentials
#   - docker CLI available and able to push to HARBOR_HOST (for test 1)
#   - Both CLI binaries built (see BUILD section below)
#
# Build the two binaries from this repo:
#   git stash                                  # or switch branches manually
#   go build -o harbor-main ./cmd/harbor       # on main
#   git stash pop                              # back to feature branch
#   go build -o harbor-feat ./cmd/harbor       # on feat/api_changes
#
# Then run:
#   chmod +x test-swagger-gaps.sh && ./test-swagger-gaps.sh

# Build the two binaries first:
# git checkout main && go build -o harbor-main ./cmd/harbor
# git checkout feat/api_changes && go build -o harbor-feat ./cmd/harbor

# Run:
# HARBOR_HOST=your.harbor.host HARBOR_USER=admin HARBOR_PASS=Harbor12345 ./test-swagger-gaps.sh

# Or set HARBOR_SCHEME=http if you're on plain HTTP.


set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
HARBOR_HOST="${HARBOR_HOST:-localhost}"        # e.g. demo.goharbor.io
HARBOR_USER="${HARBOR_USER:-admin}"
HARBOR_PASS="${HARBOR_PASS:-Harbor12345}"
HARBOR_SCHEME="${HARBOR_SCHEME:-https}"

HARBOR_MAIN_BIN="${HARBOR_MAIN_BIN:-./harbor-main}"
HARBOR_FEAT_BIN="${HARBOR_FEAT_BIN:-./harbor-feat}"

TEST_PROJECT="test-swagger-gaps-$$"
TEST_REPO="busybox"
TEST_IMAGE="${HARBOR_HOST}/${TEST_PROJECT}/${TEST_REPO}:stable"

BAD_CONFIG_FILE="/tmp/harbor-bad-config-$$.json"

# ── Colour helpers ────────────────────────────────────────────────────────────
BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
YLW=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
RST=$(tput sgr0 2>/dev/null || true)

banner()  { echo; echo "${BOLD}${CYN}══════════════════════════════════════════════════════${RST}"; echo "${BOLD}${CYN}  $*${RST}"; echo "${BOLD}${CYN}══════════════════════════════════════════════════════${RST}"; }
section() { echo; echo "${BOLD}${YLW}── $* ──${RST}"; }
info()    { echo "${GRN}▶ $*${RST}"; }
warn()    { echo "${YLW}⚠ $*${RST}"; }

# ── Run a command with both binaries and show side-by-side output ─────────────
compare() {
  local label="$1"; shift
  local args="$*"

  section "$label"
  echo "  CMD: harbor $args"
  echo

  echo "${BOLD}[main]${RST}"
  set +e
  $HARBOR_MAIN_BIN $args 2>&1
  echo "(exit $?)"
  set -e

  echo
  echo "${BOLD}[feature branch]${RST}"
  set +e
  $HARBOR_FEAT_BIN $args 2>&1
  echo "(exit $?)"
  set -e
}

# ── Cleanup trap ──────────────────────────────────────────────────────────────
cleanup() {
  echo
  info "Cleaning up test fixtures..."

  # Remove immutable rules so the repo/project can be deleted
  local rules
  rules=$(curl -sf -u "$HARBOR_USER:$HARBOR_PASS" \
    "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects/${TEST_PROJECT}/immutabletagrules" \
    2>/dev/null || echo "[]")
  echo "$rules" | python3 -c "
import sys, json
rules = json.load(sys.stdin)
for r in rules:
    print(r.get('id', ''))
" 2>/dev/null | while read -r rid; do
    [[ -z "$rid" ]] && continue
    curl -sf -u "$HARBOR_USER:$HARBOR_PASS" -X DELETE \
      "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects/${TEST_PROJECT}/immutabletagrules/${rid}" \
      2>/dev/null || true
    info "Deleted immutable rule $rid"
  done

  # Delete the repository (now unblocked)
  curl -sf -u "$HARBOR_USER:$HARBOR_PASS" -X DELETE \
    "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects/${TEST_PROJECT}/repositories/${TEST_REPO}" \
    2>/dev/null || true

  # Delete the project
  curl -sf -u "$HARBOR_USER:$HARBOR_PASS" -X DELETE \
    "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects/${TEST_PROJECT}" \
    2>/dev/null || true

  rm -f "$BAD_CONFIG_FILE"
  info "Cleanup done."
}
trap cleanup EXIT

# ── Sanity checks ─────────────────────────────────────────────────────────────
banner "Harbor swagger gap test script"

for bin in "$HARBOR_MAIN_BIN" "$HARBOR_FEAT_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "${RED}ERROR: binary not found or not executable: $bin${RST}"
    echo "Build with:"
    echo "  git checkout main  && go build -o harbor-main ./cmd/harbor"
    echo "  git checkout feat/api_changes && go build -o harbor-feat ./cmd/harbor"
    exit 1
  fi
done

info "Harbor host : ${HARBOR_HOST}"
info "Main binary : ${HARBOR_MAIN_BIN}"
info "Feat binary : ${HARBOR_FEAT_BIN}"
info "Test project: ${TEST_PROJECT}"

# ── Login both contexts ───────────────────────────────────────────────────────
section "Login"

info "Logging in (main)..."
$HARBOR_MAIN_BIN login "$HARBOR_HOST" \
  --username "$HARBOR_USER" --password "$HARBOR_PASS" 2>&1

info "Logging in (feature)..."
$HARBOR_FEAT_BIN login "$HARBOR_HOST" \
  --username "$HARBOR_USER" --password "$HARBOR_PASS" 2>&1

# ── Setup: project + immutable rule + image push ──────────────────────────────
banner "Setup"

info "Creating project '$TEST_PROJECT'..."
$HARBOR_FEAT_BIN project create "$TEST_PROJECT" \
  --public --storage-limit "-1" 2>&1

info "Creating immutable tag rule (all repos / all tags)..."
curl -sf -u "$HARBOR_USER:$HARBOR_PASS" \
  -X POST \
  -H "Content-Type: application/json" \
  "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects/${TEST_PROJECT}/immutabletagrules" \
  -d '{
    "action": "immutable",
    "disabled": false,
    "scope_selectors": {
      "repository": [{"decoration": "repoMatches", "kind": "doublestar", "pattern": "**"}]
    },
    "tag_selectors": [{"decoration": "matches", "kind": "doublestar", "pattern": "**"}],
    "template": "immutable_template"
  }' && echo " (immutable rule created)"

info "Pushing test image to ${TEST_IMAGE}..."
docker pull busybox:latest -q
docker tag busybox:latest "$TEST_IMAGE"
docker login "$HARBOR_HOST" -u "$HARBOR_USER" -p "$HARBOR_PASS" 2>&1 | tail -1
docker push "$TEST_IMAGE" 2>&1 | tail -3

# ══════════════════════════════════════════════════════════════════════════════
banner "TEST 1 — repository delete blocked by immutable tag rule (412)"
# deleteRepository is missing 412 in the swagger spec on main.
# On main:    cryptic "response status code does not match any response
#             statuses defined for this endpoint in the swagger spec (status 412)"
# On feature: human-readable error about the immutable rule precondition
# ══════════════════════════════════════════════════════════════════════════════

compare "repository delete → expect 412" \
  repo delete "${TEST_PROJECT}/${TEST_REPO}"

# ══════════════════════════════════════════════════════════════════════════════
banner "TEST 2 — list endpoint with page-size > 100 (422)"
# The CLI enforces max 100 client-side, so we go around it by calling
# listRepositories directly via the API path while the generated client
# handles the response. Use --page-size flag; client-side guard blocks >100,
# so we test the raw API call and compare how each binary handles the 422
# that Harbor sends back.
#
# NOTE: because both binaries have a client-side guard at 100, this test
# bypasses the CLI and uses curl to send page_size=99999, then pipes the
# HTTP status back as context. The interesting difference is in the
# *generated client* response parsing — trigger it by temporarily calling
# a list endpoint the CLI exposes without that guard.
#
# On main:    swagger error "status code does not match ... (status 422)"
# On feature: $ref '#/responses/422' is declared → clean error forwarded
# ══════════════════════════════════════════════════════════════════════════════

section "Sending page_size=99999 via curl (raw HTTP status)"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -u "$HARBOR_USER:$HARBOR_PASS" \
  "${HARBOR_SCHEME}://${HARBOR_HOST}/api/v2.0/projects?page_size=99999")
echo "  Harbor returned HTTP $HTTP_STATUS for page_size=99999"

if [[ "$HTTP_STATUS" == "422" ]]; then
  warn "Harbor does return 422 for oversized page-size — CLI comparison relevant."
  warn "The CLI caps at 100 client-side, so neither binary will reach the server here."
  warn "To observe the generated-client difference, rebuild without the client-side guard"
  warn "or test via a repo that the CLI doesn't cap (e.g. a custom integration test)."
else
  info "Harbor returned $HTTP_STATUS (not 422) for page_size=99999 on this instance."
fi

# ══════════════════════════════════════════════════════════════════════════════
banner "TEST 3 — configurations apply with invalid values (400 / 422)"
# updateConfigurations is missing 400 and 422 in the swagger spec on main.
# On main:    swagger error or swallowed error
# On feature: proper 400 bad-request error forwarded from Harbor
# ══════════════════════════════════════════════════════════════════════════════

cat > "$BAD_CONFIG_FILE" <<'EOF'
{
  "token_expiration": -9999
}
EOF

info "Bad config file contents:"
cat "$BAD_CONFIG_FILE"

compare "configurations apply with invalid token_expiration (-9999) → expect 400" \
  config apply -f "$BAD_CONFIG_FILE" --yes

banner "Done"
echo "Review the [main] vs [feature branch] outputs above."
echo "On main you should see the raw swagger spec error message."
echo "On the feature branch you should see the proper Harbor error."
