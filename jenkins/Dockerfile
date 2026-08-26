# Jenkins controller with the tooling the pipeline needs.
#
# The pipeline shells out to Docker (to build the app image and run Trivy,
# GitLeaks and Checkov as containers) and to Python (to run the AIOps engine),
# so both clients are installed here. The Docker socket is mounted from the
# host at runtime - this image contains the client only, not a daemon.
FROM jenkins/jenkins:lts-jdk17

USER root

# Docker CLI (client only) and Python for the engine.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg python3 python3-pip python3-venv git \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies for the AIOps engine.
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Plugins installed at build time so first boot needs no manual setup.
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Startup hooks: approve the CasC-defined pipeline script so the first build
# does not stop for manual admin approval.
COPY init.groovy.d/ /usr/share/jenkins/ref/init.groovy.d/

# Skip the setup wizard; configuration comes from casc.yaml.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc.yaml

USER jenkins
