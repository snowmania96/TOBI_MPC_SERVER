#!/bin/bash

cd `dirname $0`/..

cargo run --package msg-relay-svc --bin msg-relay-svc -- --listen 0.0.0.0:8000
