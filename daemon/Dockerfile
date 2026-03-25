FROM rust:slim@sha256:f7bf1c266d9e48c8d724733fd97ba60464c44b743eb4f46f935577d3242d81d0 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release && \
    strip target/release/openfused

FROM debian:bookworm-slim@sha256:f06537653ac770703bc45b4b113475bd402f451e85223f0f2837acbf89ab020a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/openfused /usr/local/bin/openfused
EXPOSE 2053
ENTRYPOINT ["openfused"]
CMD ["serve", "--store", "/store", "--port", "2053"]
