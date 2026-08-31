#!/bin/sh
#
# [program:jenkins]'s actual command in supervisord.conf, moved to a real
# script file rather than an inline `sh -c "...; ...; ..."` one-liner, since
# a script this long was getting hard to get right inside a single quoted
# supervisord config value.
#
# Grants Jenkins access to the mounted docker socket (see the long comment
# in supervisord.conf for why `docker run --group-add 0` alone does not
# work here), waits for sonarqube-autoconfig.sh's marker file, then hands
# off to Jenkins' own startup script as the jenkins user with SonarQube's
# host/token/network in its environment.
#
# Every variable the marker file sets must be named explicitly in the
# `export` line below - sourcing the file alone only sets them in *this*
# shell, it does not make them visible to `su`'s child process. Confirmed
# live: SONAR_HOST_URL/SONAR_TOKEN worked the moment they were listed here,
# but a later-added SONAR_NETWORK sat unused in the file for a full test
# cycle simply because this list was never updated to include it too.

chmod 666 /var/run/docker.sock 2>/dev/null || true

until [ -f /var/jenkins_home/.sonar-env ]; do
    sleep 2
done
. /var/jenkins_home/.sonar-env
export SONAR_HOST_URL SONAR_TOKEN SONAR_NETWORK

exec su jenkins -c /usr/local/bin/jenkins.sh
