FROM fluent/fluent-bit:3.2

# Upgrade base packages to pick up patched versions of libssl3, libc6,
# libgnutls30, liblzma5, libpq5 (Trivy CRITICAL/HIGH findings).
# DL3002: base image runs as root; this image requires root to read system logs.
# hadolint ignore=DL3002
USER root
# hadolint ignore=DL3005,DL3008
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

# Copy pipeline configuration
COPY fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY parsers.conf     /fluent-bit/etc/parsers.conf
COPY extract_index.lua /fluent-bit/scripts/extract_index.lua

CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
