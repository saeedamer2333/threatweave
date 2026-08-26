# ThreatWeave dashboard.
#
# The React app is a static bundle, so it is built once and then served by
# nginx, which also proxies /api to the API container. Serving both from one
# origin means the browser makes same-origin requests and no CORS is involved.

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
# .template under /etc/nginx/templates/ is picked up by the base image's own
# docker-entrypoint.d/20-envsubst-on-templates.sh, which substitutes
# environment variables into it and writes the result to
# /etc/nginx/conf.d/default.conf before nginx starts - no custom entrypoint
# needed. Do not override CMD/ENTRYPOINT: that script only runs as part of
# the base image's own startup sequence.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV API_TARGET=api:4000
EXPOSE 80
