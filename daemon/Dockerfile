FROM rust:slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release && \
    strip target/release/openfused

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openfused /usr/local/bin/openfused
EXPOSE 2053
ENTRYPOINT ["openfused"]
CMD ["serve", "--store", "/store", "--port", "2053"]
