// ABOUTME: Main entry point for @divinevideo/login
// ABOUTME: Exports OAuth client, RPC client, and utilities

import { DivineOAuth } from "./oauth";
import { DivineRpc } from "./rpc";
import type { DivineClientConfig, TokenResponse } from "./types";

export { DivineOAuth } from "./oauth";
export { DivineRpc } from "./rpc";
export { RpcError } from "./types";
export { generatePkce, validatePkce } from "./pkce";

// Backward-compatible aliases
export { DivineOAuth as KeycastOAuth } from "./oauth";
export { DivineRpc as KeycastRpc } from "./rpc";

export type {
	DivineClientConfig,
	DivineStorage,
	OAuthError,
	PkceChallenge,
	RpcRequest,
	RpcResponse,
	SignedEvent,
	StoredCredentials,
	TokenResponse,
	UnsignedEvent,
	// Backward-compatible aliases
	DivineClientConfig as KeycastClientConfig,
	DivineStorage as KeycastStorage,
} from "./types";

/**
 * Create a Divine login client with both OAuth and RPC capabilities
 *
 * @example
 * ```ts
 * import { createDivineClient } from '@divinevideo/login';
 *
 * const client = createDivineClient({
 *   serverUrl: 'https://login.divine.video',
 *   clientId: 'my-app',
 *   redirectUri: window.location.origin + '/callback',
 * });
 *
 * // Start OAuth flow
 * const { url, pkce } = await client.oauth.getAuthorizationUrl();
 * window.location.href = url;
 *
 * // After callback, exchange code
 * const tokens = await client.oauth.exchangeCode(code, pkce.verifier);
 *
 * // Use RPC client for signing
 * if (tokens.access_token) {
 *   const rpc = client.createRpc(tokens);
 *   const pubkey = await rpc.getPublicKey();
 *   const signed = await rpc.signEvent({ kind: 1, content: 'Hello!', ... });
 * }
 * ```
 */
export function createDivineClient(config: DivineClientConfig) {
	const oauth = new DivineOAuth(config);
	const nostrApi = `${config.serverUrl}/api/nostr`;

	return {
		oauth,

		/**
		 * Create an RPC client from token response
		 */
		createRpc(tokens: TokenResponse): DivineRpc | null {
			if (!tokens.access_token) {
				return null;
			}
			return new DivineRpc({
				nostrApi,
				accessToken: tokens.access_token,
			});
		},
	};
}

/** @deprecated Use createDivineClient instead */
export const createKeycastClient = createDivineClient;
