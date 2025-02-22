export const decodeBase64 = (b64: string) => {
	// Replace URL-safe characters back to standard Base64 characters
	const standardB64 = b64.replace(/-/g, "+").replace(/_/g, "/");

	// Decode
	return Uint8Array.from(atob(standardB64), (b) => b.charCodeAt(0));
};

export const encodeBase64 = (b: Uint8Array) => {
	// Encode to standard Base64
	const standardB64 = btoa(String.fromCharCode.apply(null, Array.from(b)));
	// Convert to URL-safe Base64
	return standardB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};
