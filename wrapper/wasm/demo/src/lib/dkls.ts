import { readable } from "svelte/store";
import init, { verifyingKey } from "dkls-wasm";
import wasmUrl from "dkls-wasm/dkls_wasm_bg.wasm?url";

export const loaded = init(wasmUrl);

export const coreLoaded = readable(false, (set) => {
	set(false);

	loaded.then(() => {
		set(true);
	});
});

export { verifyingKey };
