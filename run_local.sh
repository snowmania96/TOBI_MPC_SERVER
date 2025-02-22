#!/bin/sh

# Function to handle SIGINT (Ctrl-C)
cleanup() {
    echo "Ctrl-C pressed. Stopping Docker stack..."
    docker compose down
    exit 1
}

# Trap SIGINT and call the cleanup function
trap cleanup SIGINT

# Build the docker image
# First, check that the file ./dkls23_token.txt exists, and has something in it
if [ ! -f "./dkls23_token.txt" ] || ! [ -s "./dkls23_token.txt" ]; then
    echo "The file ./dkls23_token.txt does not exist."
    echo "Please create a Personal Access Token (PAT) from GitLab and save it in this file."
    echo "For more information on creating a PAT, visit: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
    echo "To issue a PAT, visit: https://gitlab.com/-/profile/personal_access_tokens"
    exit 1
fi

# If the token is not in the git credentials, add it
TOKEN=$(cat ./dkls23_token.txt)
LINE_TO_ADD="https://docker:${TOKEN}@gitlab.com"
# Check if the line exists in ~/.git-credentials
if ! grep -qF "$LINE_TO_ADD" ~/.git-credentials; then
    # If the line is not found, add it
    echo "$LINE_TO_ADD" >> ~/.git-credentials
fi


# Ensure we are using the local dev arguments
OS="$(uname)"
if [[ "$OS" == "Darwin" ]]; then
    sed -i '' 's|^// import { proxy } from '\''./proxy-local'\'';|import { proxy } from '\''./proxy-local'\'';|' ./demo_page/vite.config.ts
    sed -i '' 's|^import { proxy } from '\''./proxy'\'';|// import { proxy } from '\''./proxy'\'';|' ./demo_page/vite.config.ts
    sed -i '' 's|^var is_prod = true;|var is_prod = false;|' ./demo_page/src/lib/passkeys.ts
else
    sed -i 's|^// import { proxy } from '\''./proxy-local'\'';|import { proxy } from '\''./proxy-local'\'';|' ./demo_page/vite.config.ts
    sed -i 's|^import { proxy } from '\''./proxy'\'';|// import { proxy } from '\''./proxy'\'';|' ./demo_page/vite.config.ts
    sed -i 's|^var is_prod = true;|var is_prod = false;|' ./demo_page/src/lib/passkeys.ts
fi

# If this fails, exit the script
set -e

# Build the actual image 
docker build -t dkls-party --secret id=token,src=./dkls23_token.txt .
echo "Successfully built the dkls-party image!"


# Up the docker stack
echo "Starting docker stack..."
docker compose up --build -d
echo "Docker stack running"

# Now, if the script fails, don't exit the script
set +e

# Run the frontend in dev mode
echo "Starting the node server..."
cd ./demo_page
npm install
npm run dev

# Add an additional trap here to handle script exit
trap - SIGINT
echo "Script completed or exited. Stopping Docker stack..."
docker compose down