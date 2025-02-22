export const proxy = {
	"^/party-0/.*": {
		target: "http://localhost:9081",
		rewrite: (path) => path.replace(/^\/party-0/, ""),
	},

	"^/party-1/.*": {
		target: "http://localhost:9082",
		rewrite: (path) => path.replace(/^\/party-1/, ""),
	},

	"^/party-2/.*": {
		target: "http://localhost:9083",
		rewrite: (path) => path.replace(/^\/party-2/, ""),
	},

	"/v1/msg-relay": {
		target: "ws://localhost:8080",
		ws: true,
	},
};
