# ThreatWeave

**AIOps security alert prioritisation for SMEs on AWS.** One container runs a Jenkins
DevSecOps pipeline, the AIOps engine, an API and a web dashboard.

Four scanners (SonarQube, GitLeaks, Trivy, Checkov) and a live, read-only AWS monitor feed
one engine that:

- **deduplicates** findings across tools and groups CVEs that one upgrade fixes
- **scores** every finding: `Risk = 100 × (0.45·P + 0.25·R + 0.20·A + 0.10·E)`
  (Random Forest severity, BM25 similarity to known CVEs, asset exposure, EPSS)
- **correlates** code, container and cloud findings into **attack paths**
- **explains** each one in plain language with fixed templates (no LLM)
- **advises only**: it never changes your code or your AWS account

Built as a BSc Software Engineering final-year project (Asia Pacific University, 2026).

---

## Quick look (dashboard only)

```bash
docker run -d --name threatweave \
  -p 3000:80 -p 4000:4000 -p 8080:8080 -p 50000:50000 -p 9000:9000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v threatweave-jenkins-home:/var/jenkins_home \
  -v threatweave-findings:/workspace/findings \
  saeedalameri/threatweave:latest
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| API | http://localhost:4000/api |
| Jenkins | http://localhost:8080 (admin / admin; change `JENKINS_ADMIN_PASSWORD`) |
| SonarQube | http://localhost:9000 (password generated on first boot; see `docker logs threatweave`) |

SonarQube configures itself on first boot, which takes a few minutes.

This starts the dashboard, API, Jenkins and SonarQube so you can look around. **To actually
scan, use the command in _Scan your own project_ below**: the scanners run as sibling
containers, so Jenkins needs a checkout of this repository on the host (`HOST_WORKSPACE`).

**Nothing is scanned until you say what to scan.** Settings → Pipeline target walks you
through the four fields (source folder, Terraform folder, container image, SonarQube key).
Any field left empty is skipped, never pointed at a default project.

**Want the OWASP Juice Shop demo instead?** The one-line installer sets it up with Docker
Compose when you leave the project path blank:
`curl -fsSL https://raw.githubusercontent.com/saeedamer2333/threatweave/main/scripts/install.sh | bash`

**Requirements:** Docker, and about **6 GB of free RAM** with SonarQube. On a smaller machine
add `-e SONARQUBE_AUTOSTART=false`: the SAST stage then shows as *skipped* and everything
else keeps working.

---

## Connect AWS (optional, read-only)

Either mount your AWS CLI credentials read-only:

```bash
-v ~/.aws:/root/.aws:ro -v ~/.aws:/var/jenkins_home/.aws:ro
```

or, with no credentials on the machine, enter an access key in **Settings → AWS connection**.
Typed keys are checked with AWS first and held in memory for the session only; they are
never written to disk.

Give the key read-only access only: the AWS managed **`SecurityAudit`** policy, or the
minimum policy shown in Settings (EC2, S3 and IAM describe, list and get calls). Never use
root keys or `AdministratorAccess`.

What it checks: EC2 public IPs and IMDSv2, security groups open to `0.0.0.0/0`, S3 public
access block and default encryption, IAM `AdministratorAccess` and extra access keys.

---

## Scan your own project

Scanners run as sibling containers through the Docker socket, so the host needs a checkout
of the project repository and your target folder, both passed as **host** paths:

```bash
docker run -d --name threatweave \
  -p 3000:80 -p 4000:4000 -p 8080:8080 -p 50000:50000 -p 9000:9000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v threatweave-jenkins-home:/var/jenkins_home \
  -v /path/to/threatweave:/workspace \
  -v /path/to/your-project:/target:ro \
  -e HOST_WORKSPACE=/path/to/threatweave \
  -e TARGET_PATH=/path/to/your-project \
  saeedalameri/threatweave:latest
```

Then either fill in **Settings → Pipeline target** (source directory `/target`, your
Terraform folder, your container image), or set them at install time with
`-e SCAN_SOURCE_DIR=/target -e SCAN_IAC_DIR=/target/infra -e SCAN_IMAGE=myapp:latest`.
Settings also detects the mounted project and offers to fill the fields for you. Click
**Run scan**.

On Windows, use forward slashes in paths (`D:/projects/my-app`).

---

## Environment variables

| Variable | Default | Controls |
|---|---|---|
| `JENKINS_ADMIN_ID` / `JENKINS_ADMIN_PASSWORD` | `admin` / `admin` | Jenkins login. Change it for anything but local use. |
| `SONARQUBE_AUTOSTART` | `true` | `false` skips the bundled SonarQube (saves about 3 GB RAM) |
| `SONAR_HOST_URL` / `SONAR_TOKEN` | auto | Use an external SonarQube instead |
| `HOST_WORKSPACE` | – | Host path of the project checkout (own-project mode) |
| `TARGET_PATH` | – | Host path of the project to scan |
| `SCAN_SOURCE_DIR` | empty | Source tree for GitLeaks and SonarQube, e.g. `/target`. Empty skips both. |
| `SCAN_IAC_DIR` | empty | Terraform folder for Checkov, e.g. `/target/infra`. Empty skips it. |
| `SCAN_IMAGE` | empty | Container image for Trivy, e.g. `myapp:latest`. Empty skips it. |
| `SCAN_SONAR_KEY` | empty | SonarQube project key. Empty uses the source folder's name. |

Suppression rules start empty: analysts create them with **Dismiss** on a finding.

---

## Tags

| Tag | What it is |
|---|---|
| `latest`, `2026-09-27` | Current: scan targets start empty (or from `SCAN_*`), a guided setup in Settings, no bundled suppression rules, and upgrades keep the pipeline current |
| `2026-09-26` | Session AWS keys in Settings, a read-only policy guide, live per-scanner progress |
| `2026-08-31` | Version submitted with the final-year project report |

## Other images

The same system split into separate services, for Docker Compose:
[`threatweave-api`](https://hub.docker.com/r/saeedalameri/threatweave-api) ·
[`threatweave-dashboard`](https://hub.docker.com/r/saeedalameri/threatweave-dashboard) ·
[`threatweave-jenkins`](https://hub.docker.com/r/saeedalameri/threatweave-jenkins)

**Source:** https://github.com/saeedamer2333/threatweave · **License:** MIT

> Security note: the dashboard has no login in this version. Run it on a trusted, private
> network only, never exposed to the internet.
