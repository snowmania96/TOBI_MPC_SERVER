#!/bin/sh

#
# Usage: ./dsg.sh "test message" public_key message instance_id [pid ...] [COORD]
#
set -eu

: ${DEST:="."}
: ${CHAIN_PATH:="m"}
: ${COORD:="ws://localhost:8080/v1/msg-relay"}
: ${COORD2:=${COORD}}

public_key=${1}; shift
message=${1}; shift
instance=${1}; shift

pids="$@"
if [ $# -gt 0 ] && [[ ${!#} == ws://* ]]; then
    COORD=${!#}
    pids="${pids% *}"
fi

cmd="cargo run -p dkls-party --release -q --"

date

T=0
pks=""
for p in ${pids}; do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    pks="${pks} --party ${_pk}"
    T=$(( ${T} + 1))
done

nodes=""
for p in ${pids}; do
    nodes="${nodes} --node http://localhost:$(( 8081 + ${p}))/"
done

# Create a setup message for DSG.
$cmd sign-setup \
     --instance ${instance} \
     --ttl 10 \
     --sign ${DEST}/setup_sk \
     --public-key ${public_key} \
     --chain-path ${CHAIN_PATH} \
     --message "${message}" --hash-fn SHA256 \
     --coordinator ${COORD} \
     ${pks} \
     ${nodes}
