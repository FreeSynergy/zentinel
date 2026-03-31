# FreeSynergy packaging for Zentinel Proxy
# Build: podman build -t ghcr.io/freesynergy/zentinel:latest .
FROM docker.io/library/rust:1-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential clang libclang-dev cmake libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release -p zentinel-proxy -p zentinel-gateway

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zentinel-proxy /usr/local/bin/zentinel-proxy
COPY --from=builder /build/target/release/zentinel-gateway /usr/local/bin/zentinel-gateway

EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/zentinel-proxy"]
