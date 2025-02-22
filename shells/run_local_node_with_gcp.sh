#!/bin/bash

set -e

# --storage ./data
mkdir -p data
export GCS_DEFAULT_BUCKET="tobi-testing"
export GOOGLE_APPLICATION_CREDENTIALS="credentials.json"
export REDIS_HOST="redis://localhost:6379"
AUTH_DISABLED=true RUST_LOG=debug cargo r -p tobi-server --release  -- serve  --coordinator ws://127.0.0.1:8080/v1/msg-relay  --port 8083
