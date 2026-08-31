#!/usr/bin/env bash
#
# Wires ThreatWeave up to scan a real GitHub-hosted repo with push-triggered
# scanning already working, in one run - clones the target, writes .env,
# starts the stack (including the webhook receiver), points the dashboard
# at it, creates the GitHub webhook itself when a token is given, and
# kicks off the first scan. Collapses the manual EC2 setup (clone, edit
# .env by hand, docker compose up, configure the webhook in GitHub's UI,
# set Settings in the dashboard, click Run scan) into one command.
#
# Usage:
#   ./scripts/setup-github-target.sh <github-repo-url> [branch]
#
# Run from inside an existing ThreatWeave checkout (i.e. after
# scripts/install.sh, or after cloning the repo yourself) - this script
# assumes implementation/ is already there and only handles the *target*
# side of the setup.
#
# Environment:
#   GITHUB_TOKEN   Optional. A GitHub personal access token with the
#                  'repo' scope (classic) or "Webhooks: Read and write"
#                  (fine-grained). When set, the webhook is created
#                  automatically via GitHub's API. Without it, this prints
#                  the values to enter manually in the GitHub UI instead.
#   PUBLIC_HOST    Optional. Overrides the auto-detected public address
#                  GitHub should reach (EC2 instance metadata is tried
#                  first; this machine is prompted for if that fails and
#                  the value cannot be auto-detected).

set -euo pipefail

REPO_URL="${1:?Usage: $0 <github-repo-url> [branch]}"
BRANCH="${2:-main}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
info()  { printf '%s==>%s %s\n' "$BLUE$BOLD" "$RESET" "$1"; }
ok()    { printf '%s  ok%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '%s  !!%s %s\n' "$YELLOW" "$RESET" "$1"; }
die()   { printf '%s error:%s %s\n' "$RED$BOLD" "$RESET" "$1" >&2; exit 1; }

IMPLEMENTATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$IMPLEMENTATION_DIR/docker-compose.yml" ] || die "Run this from inside a ThreatWeave checkout (docker-compose.yml not found at $IMPLEMENTATION_DIR)."
TARGET_DIR="$(dirname "$IMPLEMENTATION_DIR")/target-repo"

# ------------------------------------------------------------------ clone --
info "Cloning target repo"
if [ -d "$TARGET_DIR/.git" ]; then
    ok "Already cloned at $TARGET_DIR - pulling latest"
    git -C "$TARGET_DIR" pull --ff-only origin "$BRANCH"
else
    git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
    ok "Cloned to $TARGET_DIR"
fi

# ---------------------------------------------------------- public address --
info "Detecting public address"
PUBLIC_HOST="${PUBLIC_HOST:-}"
if [ -z "$PUBLIC_HOST" ]; then
    # EC2 instance metadata service (IMDSv2 token, falling back to IMDSv1 -
    # some AMIs still allow the unauthenticated request).
    TOKEN=$(curl -fsS --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || echo '')
    if [ -n "$TOKEN" ]; then
        PUBLIC_HOST=$(curl -fsS --max-time 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
            http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo '')
    fi
    [ -z "$PUBLIC_HOST" ] && PUBLIC_HOST=$(curl -fsS --max-time 2 \
        http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo '')
fi
if [ -z "$PUBLIC_HOST" ]; then
    if [ -t 0 ]; then
        read -r -p "  Not running on EC2 (or no public IP found) - enter the public host/IP GitHub should reach: " PUBLIC_HOST
    fi
    [ -z "$PUBLIC_HOST" ] && die "No public address available. Set PUBLIC_HOST and re-run."
fi
ok "GitHub will reach this host at $PUBLIC_HOST"

# ------------------------------------------------------------------- .env --
info "Writing .env"
cd "$IMPLEMENTATION_DIR"
WEBHOOK_SECRET=$(openssl rand -hex 32)

if [ -f .env ]; then
    # Update just the keys this script cares about rather than clobbering an
    # existing configuration (e.g. SONAR_HOST_URL a previous run set up).
    for pair in "HOST_WORKSPACE=${IMPLEMENTATION_DIR}" "TARGET_PATH=${TARGET_DIR}" \
                "WEBHOOK_SECRET=${WEBHOOK_SECRET}" "WEBHOOK_BRANCH=refs/heads/${BRANCH}"; do
        key="${pair%%=*}"
        if grep -q "^${key}=" .env; then
            sed -i "s|^${key}=.*|${pair}|" .env
        else
            echo "$pair" >> .env
        fi
    done
    ok "Updated existing .env"
else
    cat > .env <<EOF
HOST_WORKSPACE=${IMPLEMENTATION_DIR}
TARGET_PATH=${TARGET_DIR}
WEBHOOK_SECRET=${WEBHOOK_SECRET}
WEBHOOK_BRANCH=refs/heads/${BRANCH}
API_PORT=4000
JENKINS_ADMIN_ID=admin
JENKINS_ADMIN_PASSWORD=admin
EOF
    ok "Wrote new .env"
fi

# ----------------------------------------------------------------- start --
info "Starting the stack (webhook profile)"
docker compose --profile webhook up -d --build

info "Waiting for the dashboard API"
waited=0
until curl -fsS http://localhost:"${API_PORT:-4000}"/api/settings >/dev/null 2>&1; do
    sleep 5; waited=$((waited + 5))
    [ "$waited" -ge 300 ] && die "API did not respond within 5 minutes - check 'docker compose logs api'."
done
ok "API is up"

# ------------------------------------------------------------- dashboard --
info "Pointing the dashboard at /target"
curl -fsS -X PUT "http://localhost:${API_PORT:-4000}/api/settings" \
    -H 'Content-Type: application/json' \
    -d '{"pipeline":{"sourceDir":"/target"}}' >/dev/null
ok "Settings updated"

# --------------------------------------------------------------- webhook --
if [ -n "${GITHUB_TOKEN:-}" ]; then
    info "Creating the GitHub webhook via API"
    REPO_PATH=$(echo "$REPO_URL" | sed -E 's#^(https://github\.com/|git@github\.com:)##; s#\.git$##')
    RESPONSE=$(curl -fsS -w '\n%{http_code}' -X POST "https://api.github.com/repos/${REPO_PATH}/hooks" \
        -H "Authorization: Bearer ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -d "{\"name\":\"web\",\"active\":true,\"events\":[\"push\"],\"config\":{\"url\":\"http://${PUBLIC_HOST}:9000/webhook\",\"content_type\":\"json\",\"secret\":\"${WEBHOOK_SECRET}\"}}" \
        2>&1) || true
    STATUS="${RESPONSE##*$'\n'}"
    if [ "$STATUS" = "201" ]; then
        ok "Webhook created on ${REPO_PATH}"
    else
        warn "Could not create the webhook automatically (HTTP ${STATUS}) - check GITHUB_TOKEN has the right scope."
        warn "Add it manually instead:"
        printf '      Payload URL : http://%s:9000/webhook\n' "$PUBLIC_HOST"
        printf '      Secret      : %s\n' "$WEBHOOK_SECRET"
        printf '      Events      : push\n'
    fi
else
    warn "GITHUB_TOKEN not set - add the webhook manually in GitHub:"
    printf '      Repo        : %s -> Settings -> Webhooks -> Add webhook\n' "$REPO_URL"
    printf '      Payload URL : http://%s:9000/webhook\n' "$PUBLIC_HOST"
    printf '      Content type: application/json\n'
    printf '      Secret      : %s\n' "$WEBHOOK_SECRET"
    printf '      Events      : push\n'
fi

# ------------------------------------------------------------- first scan --
info "Triggering the first scan"
curl -fsS -X POST "http://localhost:${API_PORT:-4000}/api/pipeline/run" >/dev/null
ok "Scan started"

cat <<EOF

${GREEN}${BOLD}Done.${RESET} ${REPO_URL} (${BRANCH}) is wired up.

  Dashboard   ${BOLD}http://${PUBLIC_HOST}:3000${RESET}
  Jenkins     ${BOLD}http://${PUBLIC_HOST}:8080${RESET}   ${DIM}(admin / admin - change this)${RESET}

From now on, a push to ${BRANCH} reaches the webhook receiver, which pulls
the new commit; Jenkins' own poll (every 5 minutes) picks it up from there.
EOF
