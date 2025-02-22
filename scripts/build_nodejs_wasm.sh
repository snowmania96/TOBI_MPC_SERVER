#!/bin/bash

cd `dirname $0`/..

# rustup target add wasm32-unknown-unknown
# cargo install wasm-opt
# cargo install wasm-pack
# cargo install wasm-bindgen
# cargo install wasm-bindgen-cli
wasm-pack build --target nodejs wrapper/wasm

rsync -avh --delete --exclude='snippets' --exclude='package.json' --exclude='node_modules' --exclude='.git' wrapper/wasm/pkg/ wrapper/wasm/local/ 
