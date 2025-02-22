import { writable } from "svelte/store";
import type { Keyshare } from "dkls-wasm";

export type WalletInfo = {
	n: number;
	t: number;
	// Hex string representing raw public key
	publicKey: string;
};

export const cloudPublicKeys = writable<Record<string, WalletInfo>>({});

export const keyshares = writable<Keyshare[]>([]);
