#!/bin/sh
# All-in-one entrypoint: fill in whatever was not passed with -e, then start
# every process (Jenkins, API, dashboard, SonarQube) with those values.
#
#   HOST_WORKSPACE, TARGET_PATH  from this container's own mounts (the
#                                scanners run as sibling containers and need
#                                real host paths)
#   SCAN_SOURCE_DIR, SCAN_IAC_DIR, SCAN_SONAR_KEY
#                                from the project mounted at /target
#
# A value given with -e always wins, even an empty one. Detection lives in
# aiops_engine/target_detect.py, shared with the dashboard's Settings page.
# If it fails, ThreatWeave still starts - the values can be set in Settings.

DETECT=/workspace/aiops_engine/target_detect.py

if [ -f "$DETECT" ]; then
    if detected="$(python3 "$DETECT" startup-env)"; then
        eval "$detected"
    else
        echo "[threatweave] automatic detection failed - set scan targets in Settings" >&2
    fi
fi

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/threatweave.conf
