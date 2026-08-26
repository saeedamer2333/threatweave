# ThreatWeave, all-in-one.
#
# Jenkins, the API (Node + the Python engine) and the dashboard (nginx) as
# three processes in one container, managed by supervisord. This is an
# alternative to docker-compose.yml's three separate images - same code,
# packaged differently for a single `docker run` with everything configured
# through environment variables, the way an appliance-style tool (GitLab CE's
# all-in-one image is the model this follows) usually ships.
#
# Trade-off, stated plainly: one container means one thing to restart/update
# for any change, and Jenkins' need for host-level Docker-socket access now
# sits alongside the web-facing dashboard/API processes rather than isolated
# in its own container. Prefer docker-compose.yml if independent restarts,
# smaller per-service images or that isolation are wanted; use this when a
# single `docker run` matters more than either.

# ---- Stage: frontend build ----
FROM node:22-alpine AS frontend-build
WORKDIR /app
COPY dashboard/frontend/package*.json ./
RUN npm ci
COPY dashboard/frontend/. .
RUN npm run build

# ---- Stage: backend build ----
FROM node:22-alpine AS backend-build
WORKDIR /app
COPY dashboard/backend/package*.json ./
RUN npm ci
COPY dashboard/backend/. .
RUN npm run build

# ---- Final: everything in one image ----
FROM jenkins/jenkins:lts-jdk17
USER root

# Docker CLI (client only - the socket is mounted from the host at runtime),
# Python for the engine, nginx to serve the dashboard, supervisor to run all
# three processes, and Node 22 for the API (the base image ships neither).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg python3 python3-pip python3-venv git \
        nginx supervisor \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies for the AIOps engine.
COPY jenkins/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Jenkins plugins, CasC config and the pipeline-approval hook - baked in via
# the official image's /usr/share/jenkins/ref/ convention, which seeds
# /var/jenkins_home/ on first boot only (never overwrites an existing
# volume, so upgrades don't clobber configuration made through the UI).
COPY jenkins/plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
COPY jenkins/init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/
# casc.yaml's job-dsl script reads this file directly at CasC-init time
# (readFileFromWorkspace cannot be used that early), so it needs to exist at
# this exact path once seeded - see the comment in casc.yaml itself.
COPY Jenkinsfile /usr/share/jenkins/ref/Jenkinsfile
COPY jenkins/casc.yaml /usr/share/jenkins/ref/casc.yaml

ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/usr/share/jenkins/ref/casc.yaml

# The pipeline's paths (WORKSPACE_DIR, ENGINE_DIR, ... in the Jenkinsfile)
# are hardcoded to /workspace, matching what docker-compose.yml bind-mounts
# there. Baking the engine in at that same path means Jenkins pipeline runs
# and the API's on-demand engine invocation share the exact same files and
# findings/ output - no cross-container sync to worry about, since they are
# now the same filesystem. Override with -v to scan a real checkout instead
# (see README: HOST_WORKSPACE is still required for that - baking the code
# in here does not remove the sibling-container scanning constraint).
WORKDIR /workspace
COPY aiops_engine ./aiops_engine
COPY aws_monitor ./aws_monitor
COPY infra ./infra
RUN mkdir -p ./findings/scan-inputs /target \
    && chown -R jenkins:jenkins /workspace

# API: compiled NestJS output plus its own production node_modules.
WORKDIR /app
ENV NODE_ENV=production
COPY dashboard/backend/package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=backend-build /app/dist ./dist
ENV FINDINGS_DIR=/workspace/findings \
    AIOPS_OUTPUT=/workspace/findings/aiops-output.json \
    HISTORY_FILE=/workspace/findings/history.json \
    ENGINE_DIR=/workspace/aiops_engine \
    SUPPRESSION_RULES=/workspace/aiops_engine/suppression_rules.json \
    AWS_MONITOR=/workspace/aws_monitor/monitor.py \
    PYTHON_BIN=python3 \
    PORT=4000

# Dashboard: static build served by nginx, proxying /api to localhost:4000 -
# no cross-container DNS resolution to worry about, unlike the split image.
COPY --from=frontend-build /app/dist /usr/share/nginx/html
COPY nginx-allinone.conf /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

COPY supervisord.conf /etc/supervisor/conf.d/threatweave.conf

EXPOSE 80 4000 8080 50000
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/threatweave.conf"]
