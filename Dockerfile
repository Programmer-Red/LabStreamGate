FROM rust:1.95-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release -p wsrx --bin labstreamgate

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/labstreamgate labstreamgate \
    && install -d -o labstreamgate -g labstreamgate /var/lib/labstreamgate

COPY --from=builder /src/target/release/labstreamgate /usr/local/bin/labstreamgate

USER labstreamgate
EXPOSE 8080
VOLUME ["/var/lib/labstreamgate"]

ENV WSRX_STATE_FILE=/var/lib/labstreamgate/tunnels.json \
    WSRX_ALLOWED_TARGET_HOSTS=127.0.0.1 \
    WSRX_MAX_CONNECTIONS=4096

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["labstreamgate"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
