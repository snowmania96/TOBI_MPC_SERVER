#!/bin/bash

. ./get_env.sh
env
/usr/local/bin/msg-relay-svc --listen 0.0.0.0:8888 --peer $RELAY_URL/v1/msg-relay &
/usr/local/bin/tobi-server serve --coordinator ws://localhost:8888/v1/msg-relay
