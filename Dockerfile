FROM rust:1.78 as builder

WORKDIR /src
COPY . .

RUN cargo clean
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    set -e; \
    cargo build -p dkls-party -p msg-relay-svc --release;

FROM ubuntu:22.04

WORKDIR /app

# Copy the compiled binaries
COPY --from=builder /src/target/release/dkls-party    dkls-party
COPY --from=builder /src/target/release/msg-relay-svc msg-relay-svc

RUN apt-get update
RUN apt-get install -y ca-certificates
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata

CMD ["./msg-relay-svc"]
