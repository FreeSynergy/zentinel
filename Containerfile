# FreeSynergy packaging for Zentinel — Reverse Proxy
# Build: podman build -t ghcr.io/freesynergy/zentinel:latest .
FROM docker.io/library/rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev cmake \
    libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release -p zentinel-proxy -p zentinel-gateway

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zentinel         /usr/local/bin/zentinel
COPY --from=builder /build/target/release/zentinel-gateway /usr/local/bin/zentinel-gateway

RUN useradd -r -s /bin/false zentinel && \
    mkdir -p /etc/zentinel \
    && chown -R zentinel:zentinel /etc/zentinel

VOLUME ["/etc/zentinel"]
EXPOSE 80 443

USER zentinel
ENTRYPOINT ["/usr/local/bin/zentinel"]
CMD ["--config", "/etc/zentinel/zentinel.toml"]
