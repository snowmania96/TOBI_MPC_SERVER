#!/bin/bash

SECRET_JSON=$(curl --header "X-Vault-Token: $VAULT_TOKEN" -X GET "$VAULT_ADDR/v1/$VAULT_SECRET_PATH" | jq -r '.data.data') 
echo "secrets from vault:  $SECRET_JSON"
echo $SECRET_JSON | jq -r 'to_entries | .[] | "export \(.key)=\"\(.value)\""' > .env
. ./.env


printenv