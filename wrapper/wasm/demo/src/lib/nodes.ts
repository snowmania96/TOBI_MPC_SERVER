import {
  FinishSetupBuilder,
  genInstanceId,
  KeygenSetupBuilder,
  SignSetupBuilder,
} from "dkls-wasm";

import { type ClusterDef, SignAlgo } from "./config";
import { decodeHex } from "./hex";
const ENC_KEY_TAG = 74;
const MSG = 35;

export interface CommonStats {
  total_send: number;
  total_recv: number;
  total_wait: number;
  total_time: number;
}

export interface SetupRequest {
  instance: string; // base64 encoding
  msg?: string; // base64 encoding
}

export interface KeygenResponse extends CommonStats {
  key_id: string; // hex-string
  public_key: string; // base64
}

export interface SignResponse extends CommonStats {
  sign?: string; // base64
  recid?: number; // recovery id
  preSignId?: string; // hex-string
}

const start = async (
  endpoint: string,
  instance: Uint8Array,
  msg?: Uint8Array,
): Promise<any> => {
  let body: SetupRequest = {
    instance: btoa(instance.reduce((s, b) => s + String.fromCharCode(b), "")),
  };

  if (msg) {
    body.msg = btoa(msg.reduce((s, b) => s + String.fromCharCode(b), ""));
  }

  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (resp.status != 200) {
    console.log("resp status", endpoint, resp.status, await resp.text());
    throw new Error("status " + resp.status);
  }

  return await resp.json();
};

export async function startDkg(
  signAlgo: SignAlgo,
  endpoint: string,
  instance: Uint8Array,
  msg?: Uint8Array,
): Promise<KeygenResponse> {
  let url = "/v1/keygen";
  if (signAlgo === SignAlgo.Taproot) {
    url = "/v1/taproot/keygen";
  } else if (signAlgo === SignAlgo.EdDSA) {
    url = "/v1/eddsa/keygen";
  }
  const resp = await start(endpoint + url, instance, msg);

  return resp as KeygenResponse;
}

export async function startDsg(
  signAlgo: SignAlgo,
  endpoint: string,
  instance: Uint8Array,
  msg?: Uint8Array,
): Promise<SignResponse> {
  let url = "/v1/signgen";
  if (signAlgo === SignAlgo.Taproot) {
    url = "/v1/taproot/signgen";
  } else if (signAlgo === SignAlgo.EdDSA) {
    url = "/v1/eddsa/signgen";
  }

  const resp = await start(endpoint + url, instance, msg);
  return resp as SignResponse;
}

export async function startPreSign(
  endpoint: string,
  instance: Uint8Array,
  msg?: Uint8Array,
): Promise<SignResponse> {
  const resp = await start(`${endpoint}/v1/pre-sign`, instance, msg);

  return resp as SignResponse;
}

export async function startFinSign(
  endpoint: string,
  instance: Uint8Array,
  msg?: Uint8Array,
): Promise<SignResponse> {
  const resp = await start(`${endpoint}/v1/pre-fin`, instance, msg);

  return resp as SignResponse;
}

export function createKeygenSetup(
  signAlgo: SignAlgo,
  cluster: ClusterDef,
  participants: number,
  threshold: number,
  ttl = 10,
) {
  const instance = genInstanceId();
  const builder = new KeygenSetupBuilder();

  if (signAlgo === SignAlgo.Ecdsa) {
    for (const n of cluster.nodes.slice(0, participants)) {
      builder.addParty(n.publicKey, 0);
    }
  } else if (signAlgo === SignAlgo.Taproot || signAlgo === SignAlgo.EdDSA) {
    for (const n of cluster.nodes.slice(0, participants)) {
      builder.addParty(n.publicKey, 0);
      builder.addTag(ENC_KEY_TAG, n.encKey);
    }
  }

  const setup = builder.build(
    instance,
    ttl,
    threshold,
    cluster.setup.secretKey,
  );

  return { setup, instance };
}

export type HashFn = "SHA256" | "SHA256D" | "HASH" | "KECCAK256";

export type MessageHash = {
  sha256?: Uint8Array;
  sha256D?: Uint8Array;
  hash?: Uint8Array;
  keccak256?: Uint8Array;
};

export const messageHash = (
  signHashFn: HashFn,
  signMessage: string,
): MessageHash => {
  const message = signMessage.startsWith("0x")
    ? decodeHex(signMessage.substring(2))
    : new TextEncoder().encode(signMessage);

  switch (signHashFn) {
    case "SHA256":
      return { sha256: message };

    case "SHA256D":
      return { sha256D: message };

    case "HASH":
      return { hash: message };

    case "KECCAK256":
      return { keccak256: message };

    default:
      throw new Error("invalid hash Fn");
  }
};

export function createSignSetup(
  signAlgo: SignAlgo,
  cluster: ClusterDef,
  threshold: number,
  keyId: Uint8Array,
  message?: MessageHash,
  ttl: number = 10,
  tags?: { tag: number; value: Uint8Array }[],
) {
  const instance = genInstanceId();
  const builder = new SignSetupBuilder(keyId);

  cluster.nodes
    .slice(0, threshold)
    .forEach((n) => builder.addParty(n.publicKey));

  if (message) {
    if (message.sha256) {
      builder.withHashSha256(message.sha256);
    } else if (message.sha256D) {
      builder.withHashSha256d(message.sha256D);
    } else if (message.hash) {
      builder.withHash(message.hash);
    } else if (message.keccak256) {
      builder.withHashKeccak256(message.keccak256);
    } else {
      throw new Error("missing message");
    }
  }

  const msgToSign = message?.sha256 || message?.sha256D || message?.hash ||
    message?.keccak256;

  if (
    (msgToSign && signAlgo === SignAlgo.Taproot) ||
    signAlgo === SignAlgo.EdDSA
  ) {
    builder.addTag(MSG, msgToSign);
  }

  const msgToSign = message?.sha256 || message?.sha256D || message?.hash ||
    message?.keccak256;

  if (
    (msgToSign && signAlgo === SignAlgo.Taproot) ||
    signAlgo === SignAlgo.EdDSA
  ) {
    builder.addTag(MSG, msgToSign);
  }

  tags?.forEach(({ tag, value }) => builder.addTag(tag, value));

  const setup = builder.build(instance, ttl, cluster.setup.secretKey);

  return { setup, instance };
}

export function createFinishSetup(
  cluster: ClusterDef,
  threshold: number,
  preSignId: Uint8Array,
  message: MessageHash,
  ttl: number = 10,
  tags?: { tag: number; value: Uint8Array }[],
) {
  const instance = genInstanceId();
  const builder = new FinishSetupBuilder(preSignId);

  cluster.nodes
    .slice(0, threshold)
    .forEach((n) => builder.addParty(n.publicKey));

  console.log(message);

  if (message.sha256) {
    builder.withHashSha256(message.sha256);
  } else if (message.sha256D) {
    builder.withHashSha256d(message.sha256D);
  } else if (message.hash) {
    builder.withHash(message.hash);
  } else if (message.keccak256) {
    builder.withHashKeccak256(message.keccak256);
  } else {
    throw new Error("missing message");
  }

  tags?.forEach(({ tag, value }) => builder.addTag(tag, value));

  const setup = builder.build(instance, ttl, cluster.setup.secretKey);

  return { setup, instance };
}

export function randomSeed(count: number = 32): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(count));
}
