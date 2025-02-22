import type { Handle } from "@sveltejs/kit";

/** @type {import('@sveltejs/kit').Handle} */
export const handle: Handle = async ({ event, resolve }) => {
	const response = await resolve(event, {});

	return response;
};
