# ThreatWeave Jenkins

Pre-configured Jenkins for [ThreatWeave](https://hub.docker.com/r/saeedalameri/threatweave):
the `threatweave-pipeline` job runs SonarQube, GitLeaks, Trivy and Checkov as sibling
containers through the Docker socket, runs the read-only AWS monitor, then the AIOps engine.
It checks for new commits every 5 minutes and skips the run when nothing has changed.

For a single-command setup, use the all-in-one image
[`saeedalameri/threatweave`](https://hub.docker.com/r/saeedalameri/threatweave).

## Run

Scanner volume paths are resolved by the **host** Docker daemon, so this image needs a host
checkout of the project and its real host path:

```bash
docker run -d -p 8080:8080 -p 50000:50000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e HOST_WORKSPACE=/absolute/path/to/threatweave \
  -v /absolute/path/to/threatweave:/workspace \
  saeedalameri/threatweave-jenkins:latest
```

| Variable | Default | Controls |
|---|---|---|
| `JENKINS_ADMIN_ID` / `JENKINS_ADMIN_PASSWORD` | `admin` / `admin` | Login. Change it for anything but local use. |
| `HOST_WORKSPACE` | required | Host path of the checkout |
| `SONAR_HOST_URL` / `SONAR_TOKEN` | – | SonarQube for the SAST stage |

**Source:** https://github.com/saeedamer2333/threatweave · MIT license
