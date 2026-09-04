FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build with the pinned lockfile for reproducible, cached dependency layers.
RUN cargo build --release --bin trustmesh-api

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/trustmesh-api /usr/local/bin/trustmesh-api
COPY crates/trustmesh-api/static /app/static

ENV TRUSTMESH_STATIC_DIR=/app/static

EXPOSE 3000

ENTRYPOINT ["trustmesh-api"]
