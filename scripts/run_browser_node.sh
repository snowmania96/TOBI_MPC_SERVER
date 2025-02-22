#!/bin/bash

cd `dirname $0`/..

rustup target add wasm32-unknown-unknown
cargo install wasm-opt
cargo install wasm-pack
wasm-pack build -t web wrapper/wasm

cd wrapper/wasm/demo
npm import
rm -rf node_modules && pnpm i
env DKLS_LOCAL=yes pnpm dev
