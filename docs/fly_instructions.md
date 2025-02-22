# Fly.io deployment

This is a small demo that showcases how the distributed keygen and signatures may work, in a few configurations. There are two types of node - cloud and browser. Cloud nodes are authenticated using WebAuthn. to facillitate all this, there are several components:
- A web frontend
- 3 DKLs cloud nodes
- A message relay for each DKLs cloud node
- A message relay coordinator
- An authorization node for each DKLs node

A single docker image is build that is capable of handling each of these. To build and push this image, a `deploy.sh` script has been written, which simply builds the image for the correct target, then publishes the image to the fly.io registry. Note that to run this, you need to authorise your docker to publish.
```bash
flyctl auth login
fly auth docker
```

Launch your fly.io app, first grep the whole repository for the string `sl-dkls23-passkeys` and replace it with whatever you're calling your instance. Note that there will be many instances of this string - there is much interdependency between services. Then, launch the new app from the root of the repository
```bash
flyctl launch
```
which should ask you to copy the found configuration.
****Note that you DO need a Redis cache, so ensure you select "y" for that option****. If you miss this, you can add a redis cache by running:
```bash
flyctl redis create
```
Make a note of the credentials.

Then, run the deploy script to build and publish the app:
```bash
./deploy.sh
```

Now, there are some secrets that must be set for the app. These can be set on the command line, or online, but the following environment variables must be set. Values here are illustrative.
```bash
REDIS_HOST='<YOUR REDIS URL, E.G.land-loud-silence-30.upstash.io>'
REDIS_PORT=6379
REDIS_PASSWORD='mypassword'

AUTH_NODE_SECRET="some long string"  # Used to issue JWT (currently unused)
AUTH_NODE_DEBUG=false                # When debug is True, logging is more verbose and the cache can be inspected at <node>/cache
FLASK_HOST='::'                      # fly.io uses IPv6 internally
```
Setting this from the web UI is easiest.

Once this is configured, you can deploy the configuration.
```bash
flyctl deploy --image registry.fly.io/<YOUR IMAGE NAME HERE>:latest
```
****Note that you'll need to change the image name!****


# Local Development

First, build the WASM package. From the top directory,
```
wasm-pack build -t web wrapper/wasm
```
This code handles building setup messages, and interfaces with the web sockets.

Two things need to be changed: the compose configuration, and the frontend routing. 

To run the local development version of the compose stack, target the alternate `yaml` file
```bash 
docker compose -f docker-compose.yaml up
```

Then, toggle the routing proxy. In the file [wrapper/wasm/demo/vite.config](./wrapper/wasm/demo/vite.config.ts), change the top of the file to reflect the following:
```typescript
// Local development routing
import { proxy } from './proxy-local';
// Production routing
// import { proxy } from './proxy';
```
**When committing changes - please remember to change this back! Otherwise, deployed codes will break!**

Once that change is made, run the development instance of Node:
```bash
cd wrapper/wasm/demo
npm install
npm run build
```
This will start a local version of the demo page, which reflects file changes as they are made.

