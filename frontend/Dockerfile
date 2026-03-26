FROM nginx:1.27-alpine

# Upgrade Alpine packages to pick up patched libexpat, libpng, libxml2
# (Trivy CRITICAL/HIGH findings). hadolint ignore=DL3018
RUN apk upgrade --no-cache

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/      /usr/share/nginx/html/

EXPOSE 80
