import { loaded, verifyingKey } from "./dkls";
import { decodeHex } from "./hex";

export type SetupDefs = {
  relay: string;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
};

export enum SignAlgo {
  Ecdsa = "ecdsa",
  Taproot = "taproot",
  EdDSA = "eddsa",
}

export type WalletProviderDefs = {
  walletProviderId: string;
  walletProviderUrl: string;
};

export type NodeDef = {
  endpoint: string;
  auth_endpoint: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  encKey: Uint8Array;
};

export type ClusterDef = {
  setup: SetupDefs;
  walletProvider: WalletProviderDefs;
  nodes: Array<NodeDef>;
};

export const clusterConfig = async (): Promise<ClusterDef> => {
  await loaded;

  // Public keys are all assumed to be hex-encoded.

  // Nodes are described by environment variables. The message relay is easy,
  const msgRelay = import.meta.env.VITE_NODE_MSG_RELAY;
  const msgRelaySecret = import.meta.env.VITE_NODE_MSG_RELAY_SECRETKEY;
  const walletProviderId = import.meta.env.VITE_ASSETS_WALLET_PROVIDER_ID;
  const walletProviderUrl = import.meta.env.VITE_WALLET_PROVIDER_URL;

  if (!msgRelay) {
    throw new Error("Missing environment variable: VITE_NODE_MSG_RELAY");
  }
  if (!msgRelaySecret) {
    throw new Error(
      "Missing environment variable: VITE_NODE_MSG_RELAY_SECRETKEY",
    );
  }
  // if (!walletProviderId) {
  //   throw new Error(
  //     "Missing environment variable: VITE_ASSETS_WALLET_PROVIDER_ID",
  //   );
  // }
  // if (!walletProviderUrl) {
  //   throw new Error("Missing environment variable: VITE_WALLET_PROVIDER_URL");
  // }

  // Some unknown number of nodes is also defined, following this scheme:
  // # Must be contiguous integers starting from 0
  // VITE_NODE_AUTH_0=https://dkls23.silent.sg/auth-0
  // VITE_NODE_DKLS_0=https://dkls23.silent.sg/party-0
  // VITE_NODE_PUBKEY_0=cfa1ff5424d14eb60614d7ddf65a32243d26ddf7000d10007853d7336395efe4

  // Build up the list of nodes from the environment variables.
  const nodes: Array<NodeDef> = [];

  for (let i = 0; ; i++) {
    const auth = import.meta.env[`VITE_NODE_AUTH_${i}`];
    if (!auth) {
      // No more nodes defined.
      break;
    }

    const dkls = import.meta.env[`VITE_NODE_DKLS_${i}`];
    if (!dkls) {
      throw new Error(`Missing environment variable: VITE_NODE_DKLS_${i}`);
    }

    const pubkey = import.meta.env[`VITE_NODE_PUBKEY_${i}`];
    if (!pubkey) {
      throw new Error(`Missing environment variable: VITE_NODE_PUBKEY_${i}`);
    }

    const secretKey = import.meta.env[`VITE_NODE_SECRET_${i}`];
    if (!secretKey) {
      throw new Error(`Missing environment variable: VITE_NODE_SECRET_${i}`);
    }

    const encKey = import.meta.env[`VITE_NODE_ENC_KEY_${i}`];
    if (!encKey) {
      throw new Error(`Missing environment variable: VITE_NODE_ENC_KEY_${i}`);
    }

    nodes.push({
      endpoint: dkls,
      auth_endpoint: auth,
      publicKey: decodeHex(pubkey),
      secretKey: decodeHex(secretKey),
      encKey: decodeHex(encKey),
    });
  }

  if (nodes.length === 0) {
    throw new Error("No nodes defined");
  }

  return {
    setup: {
      relay: msgRelay,
      publicKey: verifyingKey(decodeHex(msgRelaySecret)),
      secretKey: decodeHex(msgRelaySecret),
    },

    walletProvider: {
      walletProviderId,
      walletProviderUrl,
    },

    nodes,
  };
};

export const wsUrl = (path: string) => {
  if (path.startsWith("ws://") || path.startsWith("wss://")) {
    return path;
  }

  // https: => wss:
  // http:  => ws:
  return path.replace("http", "ws");
};
