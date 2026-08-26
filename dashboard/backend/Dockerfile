# ThreatWeave API.
#
# Built in two stages so the runtime image carries only production
# dependencies and the compiled output. Python and Boto3 are installed
# because the API shells out to the AIOps engine and the AWS monitor.

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-slim
WORKDIR /app

# The API invokes the Python engine and the AWS monitor as child processes.
#
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
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist

EXPOSE 4000
CMD ["node", "dist/main"]
