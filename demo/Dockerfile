FROM rust:1-bookworm AS builder
WORKDIR /build
COPY daemon/ daemon/
RUN cd daemon && cargo build --release

FROM node:22-slim
RUN apt-get update -qq && apt-get install -y -qq jq python3 && rm -rf /var/lib/apt/lists/*
RUN npm install -g openfused

COPY --from=builder /build/daemon/target/release/openfused /usr/local/bin/openfused
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2053
ENTRYPOINT ["/entrypoint.sh"]
