#!/bin/sh
#
# Runs inside the all-in-one container as its own supervisord program.
# Waits for the bundled SonarQube to boot, replaces its default admin
# password, generates an analysis token, and writes SONAR_HOST_URL/
# SONAR_TOKEN to a marker file - which [program:jenkins]'s own startup
# command (see supervisord.conf) waits on before launching Jenkins, so
# SAST is fully configured before the pipeline job could ever run.
#
# When SONARQUBE_AUTOSTART=false, writes an empty marker immediately so
# Jenkins is never blocked waiting on a server that was never asked to
# start.

set -e

ENV_FILE=/var/jenkins_home/.sonar-env
SONAR_URL="http://localhost:9000"

if [ "${SONARQUBE_AUTOSTART:-true}" != "true" ]; then
    : > "$ENV_FILE"
    echo "SonarQube disabled (SONARQUBE_AUTOSTART=$SONARQUBE_AUTOSTART) - SAST stays off."
    exec sleep infinity
fi

echo "Waiting for SonarQube to finish booting..."
waited=0
until curl -sf "$SONAR_URL/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; do
    sleep 5; waited=$((waited + 5))
    if [ "$waited" -ge 300 ]; then
        echo "SonarQube did not become ready within 5 minutes - leaving SAST off for this boot."
        : > "$ENV_FILE"
        exec sleep infinity
    fi
done
echo "SonarQube is up"

# A random password replaces the well-known admin/admin default. Nothing in
# this project needs a human to remember it day-to-day - the pipeline
# authenticates with the token generated below - so it is only ever shown
# once, in this container's logs, for the rare case someone wants the UI.
# SonarQube rejects a password with no special character - confirmed live,
# a plain base64-derived alphanumeric string (the obvious first attempt)
# got "Password must contain at least one special character" back from the
# API - so one is appended explicitly rather than relying on the random
# charset to happen to include one.
NEW_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '=+/\n' | head -c 20)!Aa1"

if curl -sf -u admin:admin -X POST "$SONAR_URL/api/users/change_password" \
    --data-urlencode "login=admin" \
    --data-urlencode "previousPassword=admin" \
    --data-urlencode "password=$NEW_PASSWORD" >/dev/null 2>&1; then
    echo "Admin password changed"
else
    echo "Could not change the admin/admin default (already changed on a previous boot?) - trying it as the current password."
    NEW_PASSWORD="admin"
fi

TOKEN_JSON="$(curl -sf -u "admin:$NEW_PASSWORD" -X POST "$SONAR_URL/api/user_tokens/generate" \
    --data-urlencode "name=threatweave-pipeline-$(date +%s)" 2>/dev/null)" || {
    echo "Could not generate a token - leaving SAST off for this boot."
    : > "$ENV_FILE"
    exec sleep infinity
}
TOKEN="$(printf '%s' "$TOKEN_JSON" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)"
if [ -z "$TOKEN" ]; then
    echo "Unexpected response generating the token - leaving SAST off for this boot."
    : > "$ENV_FILE"
    exec sleep infinity
fi

{
    echo "SONAR_HOST_URL=$SONAR_URL"
    echo "SONAR_TOKEN=$TOKEN"
    # The scanner runs as a *sibling* container (its own network namespace),
    # so "localhost:9000" above only resolves correctly from inside this
    # container itself - confirmed live, a real pipeline run got exit code 1
    # because the scanner container's own localhost obviously isn't this
    # container's SonarQube. `--network container:<this container's own id>`
    # makes the scanner share this container's network namespace directly,
    # so SONAR_HOST_URL's localhost then means the same thing for both -
    # no shared bridge network needed, and the Jenkinsfile already reads
    # SONAR_NETWORK from the environment exactly like the two vars above.
    echo "SONAR_NETWORK=container:$(hostname)"
} > "$ENV_FILE"

echo ""
echo "=========================================================="
echo "SonarQube admin password: $NEW_PASSWORD"
echo "Save this now - it is not stored anywhere and only shown"
echo "here, once. Only needed to open the SonarQube UI yourself;"
echo "the pipeline authenticates with the generated token."
echo "=========================================================="
echo ""
echo "SAST is now fully configured."

# Stay alive so supervisord doesn't treat a clean exit as a crash to restart.
exec sleep infinity
