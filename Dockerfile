FROM alpine:3.23

LABEL org.opencontainers.image.source="https://github.com/ivenos/wg-direct" \
      org.opencontainers.image.description="Minimal WireGuard image for site-to-site tunnels" \
      org.opencontainers.image.licenses="GPL-3.0-only"

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    iproute2 \
    python3

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 51820/udp

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wg show 2>/dev/null | grep -q "interface" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
