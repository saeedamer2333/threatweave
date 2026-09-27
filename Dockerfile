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

# ---- Stage: SonarQube distribution ----
# Bundled by default (see ENABLE_SONARQUBE-equivalent SONARQUBE_AUTOSTART
# below) so a single `docker run` gets a fully working SAST stage with zero
# manual setup - copied from the real, official image rather than
# reimplemented, so its own JVM tuning and Elasticsearch bootstrap logic is
# reused unmodified.
FROM sonarqube:community AS sonarqube-src
# The image runs as its own non-root "sonarqube" user by default, which
# lacks write access to delete anything under lib/extensions/ (confirmed
# live - permission denied) - root is needed for this one step only.
USER root
# Drops language analyzers this project never scans (this repo and every
# real target used against it so far are Python/JS/TS) - ~148MB of the
# ~325MB bundled plugin payload (C#/VB.NET, Go, Java, Kotlin, PHP, Ruby,
# Rust, Scala), plus the classloading/metaspace overhead of loading them at
# boot. Deleted *here*, in the source stage, not via a later `RUN rm` on the
# copy in the final stage - Docker layers are append-only, so a delete after
# a COPY only hides the files from the running container, it does not
# actually shrink the image (confirmed live: image size was unchanged after
# doing it that way first). Deleting before the COPY means the final
# stage's layer never contains this data in the first place.
RUN rm -f /opt/sonarqube/lib/extensions/sonar-csharp-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-vbnet-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-go-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-java-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-java-symbolic-execution-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-kotlin-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-php-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-ruby-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-rust-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-scala-plugin-*.jar \
          /opt/sonarqube/lib/extensions/sonar-flex-plugin-*.jar

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

# SonarQube's own distribution, plus a dedicated user - the official image
# also uses uid 1000 for its "sonarqube" user, which collides with this
# base image's "jenkins" user (also uid 1000), so a distinct uid is required
# rather than reusing whatever the source image shipped.
COPY --from=sonarqube-src /opt/sonarqube /opt/sonarqube
# SonarQube's own bundled JRE - it needs a newer Java than the Jenkins base
# image ships (confirmed live: SonarQube's class files require Java 21+,
# jenkins/jenkins:lts-jdk17 only provides 17, and both images happen to use
# the exact same /opt/java/openjdk path for their own JDK, so this has to
# land somewhere else and be pointed at explicitly for the sonarqube
# process only - see JAVA_HOME in supervisord.conf's [program:sonarqube].
COPY --from=sonarqube-src /opt/java/openjdk /opt/java-sonar
RUN groupadd -g 1001 sonarqube \
    && useradd -u 1001 -g sonarqube -d /opt/sonarqube -s /bin/bash -M sonarqube \
    && mkdir -p /opt/sonarqube/data /opt/sonarqube/logs /opt/sonarqube/extensions /opt/sonarqube/temp \
    && chown -R sonarqube:sonarqube /opt/sonarqube \
    # entrypoint.sh hardcodes the literal path '/opt/java/openjdk/bin/java'
    # rather than reading $JAVA_HOME - confirmed live (setting JAVA_HOME in
    # supervisord's environment= had no effect, the script never reads it) -
    # so the only working fix is patching the one script that hardcodes it,
    # pointing it at the relocated JRE from the COPY above.
    && sed -i 's|/opt/java/openjdk|/opt/java-sonar|' /opt/sonarqube/docker/entrypoint.sh
# Bypasses the strict OS-level vm.max_map_count check Elasticsearch (bundled
# inside SonarQube) normally requires - matches docker-compose.yml's own
# sonarqube service, which sets the same override for the same reason.
ENV SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
# Included by default - set to "false" (`-e SONARQUBE_AUTOSTART=false`) to
# run without it, e.g. on a host that can't spare the extra ~3GB.
ENV SONARQUBE_AUTOSTART=true
# Modest heap trims below SonarQube's own 512m/512m/512m stock defaults -
# only for web and the compute engine, which have real headroom for this
# project's actual scan sizes (confirmed live: a real scan completed fine
# at these levels). search (the bundled Elasticsearch) is deliberately left
# at its stock 512m - it is the one component with a real minimum below
# which it stops booting reliably, so it is not a safe place to save RAM.
# Override any of the three yourself (`-e SONAR_CE_JAVAOPTS=...`) to raise
# them back up if a genuinely large scan needs more.
ENV SONAR_WEB_JAVAOPTS="-Xmx384m -Xms128m -XX:+HeapDumpOnOutOfMemoryError"
ENV SONAR_CE_JAVAOPTS="-Xmx384m -Xms128m -XX:+HeapDumpOnOutOfMemoryError"
COPY sonarqube-autoconfig.sh /usr/local/bin/sonarqube-autoconfig.sh
COPY jenkins-entrypoint.sh /usr/local/bin/jenkins-entrypoint.sh
RUN chmod +x /usr/local/bin/sonarqube-autoconfig.sh /usr/local/bin/jenkins-entrypoint.sh

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
# `.override` makes jenkins.sh re-copy it into JENKINS_HOME on every start.
# Without it the file is copied only once, so anyone upgrading the image but
# keeping their jenkins-home volume would keep running the old pipeline.
COPY Jenkinsfile /usr/share/jenkins/ref/Jenkinsfile.override
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
    FIRST_SEEN_FILE=/workspace/findings/first_seen.json \
    ENGINE_DIR=/workspace/aiops_engine \
    SUPPRESSION_RULES=/workspace/aiops_engine/suppression_rules.json \
    AWS_MONITOR=/workspace/aws_monitor/monitor.py \
    AWS_STATUS_CHECK=/workspace/aws_monitor/status_check.py \
    PYTHON_BIN=python3 \
    PORT=4000

# Dashboard: static build served by nginx, proxying /api to localhost:4000 -
# no cross-container DNS resolution to worry about, unlike the split image.
COPY --from=frontend-build /app/dist /usr/share/nginx/html
COPY nginx-allinone.conf /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

COPY supervisord.conf /etc/supervisor/conf.d/threatweave.conf

EXPOSE 80 4000 8080 50000 9000
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/threatweave.conf"]
