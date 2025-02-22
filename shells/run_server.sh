#!/bin/bash

export AUTH_DISABLED=true
/usr/local/bin/tobi-server serve --storage ./data --coordinator ws://"${COORD_URL}"/v1/msg-relay


