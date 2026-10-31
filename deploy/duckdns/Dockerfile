# Caddy with the DuckDNS DNS provider plugin, so it can solve the ACME DNS-01
# challenge (no need for port 80, which fictorium already owns).
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/duckdns

FROM caddy:2
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
