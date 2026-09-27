# ThreatWeave Dashboard

React dashboard for [ThreatWeave](https://hub.docker.com/r/saeedalameri/threatweave), served
by nginx. Shows the health score, the noise-reduction funnel, ranked findings with the
reason behind every score, attack paths with plain-language explanations, history, and
settings (including the AWS connection and a read-only policy guide).

It proxies `/api` to the [ThreatWeave API](https://hub.docker.com/r/saeedalameri/threatweave-api).
For a single-command setup, use the all-in-one image
[`saeedalameri/threatweave`](https://hub.docker.com/r/saeedalameri/threatweave).

## Run

```bash
docker run -d -p 3000:80 -e API_TARGET=host.docker.internal:4000 \
  saeedalameri/threatweave-dashboard:latest
```

| Variable | Default | Controls |
|---|---|---|
| `API_TARGET` | `api:4000` | Where nginx sends `/api` requests (host:port) |

> The dashboard has no login in this version. Use it on a trusted, private network only.

**Tags:** `latest` = `2026-09-27` (current) · `2026-09-26` · `2026-09-02` (version at project submission)

**Source:** https://github.com/saeedamer2333/threatweave · MIT license
