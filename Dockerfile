FROM alpine:3.20

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    iproute2 \
    python3

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
