# ThreatWeave API

NestJS API and the Python AIOps engine for [ThreatWeave](https://hub.docker.com/r/saeedalameri/threatweave):
reads scanner reports, deduplicates, scores, correlates findings into attack paths and
explains them. Serves results to the
[dashboard](https://hub.docker.com/r/saeedalameri/threatweave-dashboard) and triggers the
[Jenkins pipeline](https://hub.docker.com/r/saeedalameri/threatweave-jenkins).

For a single-command setup, use the all-in-one image
[`saeedalameri/threatweave`](https://hub.docker.com/r/saeedalameri/threatweave).

## Run

```bash
docker run -d -p 4000:4000 \
  -v threatweave-findings:/app/findings \
  -v ~/.aws:/root/.aws:ro \
  saeedalameri/threatweave-api:latest
```

The `~/.aws` mount is optional. Without it, AWS keys can be entered on the dashboard's
Settings page for the session (held in memory only).

Useful endpoints: `GET /api/findings`, `GET /api/findings/clusters`, `POST /api/scan`,
`GET /api/aws/status`, `POST /api/pipeline/run`.

| Variable | Default | Controls |
|---|---|---|
| `PORT` | `4000` | Listen port |
| `JENKINS_URL` | `http://jenkins:8080` | Jenkins to trigger for full scans |
| `JENKINS_ADMIN_ID` / `JENKINS_ADMIN_PASSWORD` | `admin` | Jenkins credentials |
| `FINDINGS_DIR`, `AIOPS_OUTPUT`, `HISTORY_FILE` | under `/app/findings` | Where engine output is read and written |

**Tags:** `latest` = `2026-09-27` (current) · `2026-09-26` · `2026-09-02` (version at project submission)

**Source:** https://github.com/saeedamer2333/threatweave · MIT license
