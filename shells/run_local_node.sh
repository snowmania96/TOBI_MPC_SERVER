#!/bin/bash

set -e
mkdir -p data
AUTH_DISABLED=true RUST_LOG=debug cargo r -p tobi-server --release  -- serve  --coordinator ws://127.0.0.1:8080/v1/msg-relay --storage ./data --port 8083
