#!/bin/sh

set -eux

_tag=${1:-"latest"}

docker build \
       --platform linux/amd64 \
       -t dkls-party \
       -t registry.fly.io/sl-dkls23-passkeys:${_tag} \
       --secret id=token,src=./dkls23_token.txt \
       .

docker push registry.fly.io/sl-dkls23-passkeys:${_tag}

# For some reason, this has to be deployed twice to work properly - otherwise the Rust servers can't be reached??
flyctl deploy --image registry.fly.io/sl-dkls23-passkeys:${_tag} --remote-only
flyctl deploy --image registry.fly.io/sl-dkls23-passkeys:${_tag} --remote-only

flyctl status