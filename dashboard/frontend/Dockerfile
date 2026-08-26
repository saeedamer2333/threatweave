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
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
