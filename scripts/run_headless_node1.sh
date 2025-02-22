#!/bin/bash

cd `dirname $0`/..

[ -d data2 ] || mkdir data2
RUST_LOG=debug cargo run --package dkls-party --bin dkls-party -- serve --storage ./data2 --party-key ./testdata/party_1_sk --setup-vk-file ./testdata/setup_vk --coordinator ws://localhost:8000/v1/msg-relay --listen 0.0.0.0:8082
