#!/bin/bash

set -e

RUST_LOG=debug cargo r -p msg-relay-svc --release  -- --listen 0.0.0.0:8080
