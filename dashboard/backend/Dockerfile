# ThreatWeave API.
#
# Built in two stages so the runtime image carries only production
# dependencies and the compiled output. Python and Boto3 are installed
# because the API shells out to the AIOps engine and the AWS monitor.
#
# Build context is the implementation/ directory (not this folder), so the
# engine and monitor can be baked in - see docker-compose.yml's `api.build`.
# That makes the published image runnable standalone via `docker run`, with
# no bind mount required. docker-compose.yml still bind-mounts the live
# checkout over these baked-in paths for local development, so editing
# aiops_engine/ during development needs no rebuild - the ENV defaults below
# are only what a plain `docker run` (no compose, no bind mount) falls back
# on.

FROM node:22-alpine AS build
WORKDIR /app
COPY dashboard/backend/package*.json ./
RUN npm ci
COPY dashboard/backend/. .
RUN npm run build

FROM node:22-slim
WORKDIR /app

# Debian rather than Alpine: scikit-learn and numpy publish manylinux wheels
# but no musl ones, so pip on Alpine falls back to compiling them from source
# and fails during metadata generation. Installing from wheels here keeps the
# image build fast and reproducible.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
    && pip3 install --no-cache-dir --break-system-packages \
        boto3 scikit-learn rank-bm25 joblib \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
COPY dashboard/backend/package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist

# The Python engine and AWS monitor, baked in so this image works standalone.
COPY aiops_engine ./aiops_engine
COPY aws_monitor ./aws_monitor
RUN mkdir -p ./findings

ENV FINDINGS_DIR=/app/findings \
    AIOPS_OUTPUT=/app/findings/aiops-output.json \
    HISTORY_FILE=/app/findings/history.json \
    ENGINE_DIR=/app/aiops_engine \
    SUPPRESSION_RULES=/app/aiops_engine/suppression_rules.json \
    AWS_MONITOR=/app/aws_monitor/monitor.py \
    PYTHON_BIN=python3

EXPOSE 4000
CMD ["node", "dist/main"]
