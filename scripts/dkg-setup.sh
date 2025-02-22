#!/bin/sh

#
# Usage ./dkg-setup.sh N T INSTANCE_ID [COORDINATOR_URL]
#
# Generate key: threshold 3, partcipants 5
#

set -eu

_b=$(dirname $0)

: ${DEST:="${_b}/../../../testdata"}

# Three arguments, N (int), T (int), INST (32 bytes hex)
# Check if exactly 3 arguments are passed
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $0 <N> <T> <INSTANCE_ID> [COORDINATOR_URL]"
    exit 1
fi

# Validate if the first and second arguments are integers
if ! [[ $1 =~ ^-?[0-9]+$ ]] || ! [[ $2 =~ ^-?[0-9]+$ ]]; then
    echo "Error: The first two arguments must be integers."
    exit 1
fi

# Validate if the third argument is a 32-byte hex string
if ! [[ $3 =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "Error: The third argument must be a 32-byte hex string."
    exit 1
fi

# If a fourth argument is provided, validate if it is a websockets URL
if [ "$#" -eq 4 ]; then
    if ! [[ $4 =~ ^ws[s]?:// ]]; then
        echo "Error: The fourth argument must be a valid websocket URL starting with ws:// or wss://"
        exit 1
    fi
fi

# If all validations pass, process the arguments
N=$1
T=$2
INST=$3


# Print the URL if it is provided
if [ "$#" -eq 4 ]; then
    COORD=$4
else
    COORD="ws://localhost:8080/v1/msg-relay"
fi


cmd="cargo run -p dkls-party -q --release -- "

#
# Calculate public keys of each party.
# It will make sure that crates/dkls-party is up to
# update and build the release profile if necessary.
#
all_party_sk=""
all_party_pk=""
for p in $(jot ${N} 0); do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    eval party_${p}_pk=${_pk}
    all_party_pk="${all_party_pk} --party ${_pk}"
    all_party_sk="${all_party_sk} --party ${DEST}/party_${p}_sk"
done

nodes=""
for p in $(jot ${N} 8081); do
    nodes="${nodes} --node http://localhost:${p}/"
done

#
# Now we are ready to generate and publish a setup message for
# distributed key generation. The setup message contains parameters
# N, T and PK of all parties that will participate in key generation.
# The message will be signed by given secret key a published to a
# given message relay (coordinator).
#
$cmd keygen-setup \
     --ttl 10 \
     --threshold ${T} \
     --sign ${DEST}/setup_sk \
     --coordinator ${COORD} \
     --instance ${INST} \
     ${all_party_pk} \
     ${nodes}
