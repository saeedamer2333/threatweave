#!/usr/bin/env bash
#
# Fully automates the SonarQube setup a human would otherwise do by hand in
# its web UI: start the server, wait for it to boot, replace the insecure
# default admin password, generate an analysis token, and wire both
# SONAR_HOST_URL/SONAR_TOKEN into .env - so this one script is the entire
# SAST setup, no browser required.
#
#   scripts/setup-sonarqube.sh
#
# Idempotent: does nothing if .env already has a SONAR_TOKEN, so re-running
# this (e.g. from install.sh on an upgrade) never silently rotates a token
# something else might already be relying on.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

SONAR_URL="${SONAR_URL:-http://localhost:9000}"
ENV_FILE=".env"

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
info() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$1"; }
ok()   { printf '%s  ok%s %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%s  !!%s %s\n' "$YELLOW" "$RESET" "$1"; }

if [ -f "$ENV_FILE" ] && grep -q '^SONAR_TOKEN=.\+' "$ENV_FILE" 2>/dev/null; then
    ok "SonarQube already configured in $ENV_FILE - nothing to do."
    exit 0
fi

info "Starting the SonarQube container (needs ~3GB RAM; safe to call if already running)"
docker compose --profile sast up -d sonarqube

info "Waiting for SonarQube to finish booting at $SONAR_URL"
waited=0
until curl -sf "$SONAR_URL/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; do
    sleep 5; waited=$((waited + 5))
    if [ "$waited" -ge 300 ]; then
        warn "SonarQube did not become ready within 5 minutes - skipping SAST auto-setup."
        warn "Re-run this script once 'docker compose --profile sast up -d sonarqube' has fully started."
        exit 0
    fi
done
ok "SonarQube is up"

# A random password replaces the well-known admin/admin default - nothing
# in this project needs a human to remember it day-to-day (the pipeline
# authenticates with the token generated below, not this password), so it
# is only ever shown once, at the end, for the rare case someone wants to
# open the SonarQube UI themselves.
NEW_PASSWORD="$(openssl rand -base64 18 2>/dev/null | tr -d '=+/' | head -c 24)"
if [ -z "$NEW_PASSWORD" ]; then
    NEW_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 24)"
fi

info "Replacing the default admin password"
if curl -sf -u admin:admin -X POST "$SONAR_URL/api/users/change_password" \
    --data-urlencode "login=admin" \
    --data-urlencode "previousPassword=admin" \
    --data-urlencode "password=$NEW_PASSWORD" >/dev/null 2>&1; then
    ok "Admin password changed"
else
    # Already changed by a previous partial run, or by hand - fall back to
    # what a human would already know, rather than failing outright.
    warn "Could not change the admin/admin default (already changed?) - trying it as the current password."
    NEW_PASSWORD="admin"
fi

info "Generating an analysis token"
TOKEN_JSON="$(curl -sf -u "admin:$NEW_PASSWORD" -X POST "$SONAR_URL/api/user_tokens/generate" \
    --data-urlencode "name=threatweave-pipeline-$(date +%s)" 2>/dev/null)" || {
    warn "Could not generate a token - SAST will stay disabled. Re-run this script once you've confirmed the admin password."
    exit 0
}
TOKEN="$(printf '%s' "$TOKEN_JSON" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)"
if [ -z "$TOKEN" ]; then
    warn "Unexpected response generating the token - SAST will stay disabled."
    exit 0
fi
ok "Token generated"

info "Writing SONAR_HOST_URL / SONAR_TOKEN into $ENV_FILE"
touch "$ENV_FILE"
if grep -q '^SONAR_HOST_URL=' "$ENV_FILE"; then
    sed -i "s|^SONAR_HOST_URL=.*|SONAR_HOST_URL=http://sonarqube:9000|" "$ENV_FILE"
else
    echo "SONAR_HOST_URL=http://sonarqube:9000" >> "$ENV_FILE"
fi
if grep -q '^SONAR_TOKEN=' "$ENV_FILE"; then
    sed -i "s|^SONAR_TOKEN=.*|SONAR_TOKEN=$TOKEN|" "$ENV_FILE"
else
    echo "SONAR_TOKEN=$TOKEN" >> "$ENV_FILE"
fi

info "Restarting the pipeline containers to pick up the new SAST config"
docker compose up -d
ok "SAST is now fully configured - the next scan includes SonarQube automatically"

cat <<EOF

${BOLD}SonarQube admin password:${RESET} $NEW_PASSWORD
${YELLOW}Save this now${RESET} - it is not stored anywhere and cannot be shown again.
Only needed if you want to open http://localhost:9000 yourself; the
pipeline itself authenticates with the generated token, not this password.

EOF
