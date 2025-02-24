FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef

WORKDIR /app

ENV HOST 0.0.0.0

FROM chef AS planner
COPY . .

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

ARG GIT_CREDENTIALS
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    set -e; \
    git config --global credential.helper store; \
    git config --global url."https://".insteadOf git://; \
    echo "${GIT_CREDENTIALS}" > ~/.git-credentials;

RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build -p tobi-server -p msg-relay-svc --release


FROM debian:bookworm-slim as runtime

WORKDIR /app

RUN apt-get update;
RUN apt-get install -y ca-certificates curl jq;
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata;

COPY --from=builder /app/target/release/tobi-server /usr/local/bin/tobi-server
COPY --from=builder /app/target/release/msg-relay-svc /usr/local/bin/msg-relay-svc
COPY ./shells/* ./

ENV PORT=8080
EXPOSE 8080

ARG MSG_RELAY_URL
ENV MSG_RELAY_URL=${MSG_RELAY_URL}

CMD /usr/local/bin/tobi-server serve --coordinator ${MSG_RELAY_URL} --port 8080
