// ABOUTME: OAuth client for Divine login authorization
// ABOUTME: Handles authorization URL generation, token exchange, and PKCE

import { generatePkce } from "./pkce";
import type {
	DivineClientConfig,
	DivineStorage,
	OAuthError,
	PkceChallenge,
	StoredCredentials,
	TokenResponse,
} from "./types";

/** Storage key for session credentials */
const STORAGE_KEY_SESSION = "divine_session";
/** Storage key for authorization handle (for silent re-auth when session expires) */
const STORAGE_KEY_HANDLE = "divine_auth_handle";
/** Storage key for PKCE verifier (survives page reload during OAuth redirect) */
const STORAGE_KEY_PKCE = "divine_pkce";
/** Storage key for OAuth state (enables multi-device email verification polling) */
const STORAGE_KEY_STATE = "divine_oauth_state";

/**
 * In-memory storage fallback when no storage is provided
 */
class MemoryStorage implements DivineStorage {
	private data = new Map<string, string>();

	getItem(key: string): string | null {
		return this.data.get(key) ?? null;
	}

	setItem(key: string, value: string): void {
		this.data.set(key, value);
	}

	removeItem(key: string): void {
		this.data.delete(key);
	}
}

/**
 * Derive public key from nsec using nostr-tools (optional peer dependency)
 * Uses dynamic import to avoid hard dependency on nostr-tools
 */
async function derivePublicKeyFromNsec(nsec: string): Promise<string> {
	try {
		// Dynamic imports - bundlers will handle these properly
		// nostr-tools is an optional peer dependency
		const [nip19, pure] = await Promise.all([
			import("nostr-tools/nip19"),
			import("nostr-tools/pure"),
		]);
		const decoded = nip19.decode(nsec);
		if (decoded.type !== "nsec") {
			throw new Error("Not a valid nsec");
		}
		return pure.getPublicKey(decoded.data);
	} catch (e) {
		throw new Error(
			`Invalid nsec or nostr-tools not installed: ${e instanceof Error ? e.message : "unknown error"}`,
		);
	}
}

/**
 * OAuth client for Divine login authorization
 */
export class DivineOAuth {
	private config: DivineClientConfig;
	private fetch: typeof globalThis.fetch;
	private storage: DivineStorage;
	private pendingPkce: PkceChallenge | null = null;

	constructor(config: DivineClientConfig) {
		this.config = config;
		this.fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
		this.storage = config.storage ?? new MemoryStorage();
	}

	/**
	 * Get stored session from storage (synchronous, no refresh)
	 * Returns null if no session exists
	 * Use getSessionWithRefresh() for automatic token refresh
	 */
	getSession(): StoredCredentials | null {
		const json = this.storage.getItem(STORAGE_KEY_SESSION);
		if (!json) return null;

		try {
			return JSON.parse(json) as StoredCredentials;
		} catch {
			return null;
		}
	}

	/**
	 * Get stored session with automatic refresh if expired or near-expiry
	 * Returns null if no session or refresh fails
	 */
	async getSessionWithRefresh(): Promise<StoredCredentials | null> {
		const credentials = this.getSession();
		if (!credentials) return null;

		// If not near expiry, return as-is
		if (!this.shouldRefresh(credentials)) {
			return credentials;
		}

		// Try to refresh if we have a refresh token
		if (credentials.refreshToken) {
			try {
				return await this.refreshSession(credentials.refreshToken);
			} catch (e) {
				// Refresh failed - clear session and return null
				console.warn("Session refresh failed:", e);
				this.storage.removeItem(STORAGE_KEY_SESSION);
				return null;
			}
		}

		// No refresh token and expired - return null
		if (this.isExpired(credentials)) {
			return null;
		}

		return credentials;
	}

	/**
	 * Get stored authorization handle (survives logout)
	 */
	getAuthorizationHandle(): string | null {
		return this.storage.getItem(STORAGE_KEY_HANDLE);
	}

	/**
	 * Clear all session data including authorization handle and PKCE
	 * Use this when user explicitly logs out - clears everything for security
	 */
	logout(): void {
		this.storage.removeItem(STORAGE_KEY_SESSION);
		this.storage.removeItem(STORAGE_KEY_HANDLE);
		this.storage.removeItem(STORAGE_KEY_PKCE);
		this.pendingPkce = null;
	}

	private saveSession(credentials: StoredCredentials): void {
		this.storage.setItem(STORAGE_KEY_SESSION, JSON.stringify(credentials));
		if (credentials.authorizationHandle) {
			this.storage.setItem(STORAGE_KEY_HANDLE, credentials.authorizationHandle);
		}
	}

	/**
	 * Generate authorization URL for OAuth flow
	 * Automatically uses stored authorization handle for silent re-auth if available
	 *
	 * @param options - Authorization options
	 * @returns Authorization URL and PKCE verifier
	 */
	async getAuthorizationUrl(
		options: {
			scopes?: string[];
			nsec?: string; // For BYOK flow - pubkey is derived automatically
			defaultRegister?: boolean;
			authorizationHandle?: string; // Override stored handle for silent re-authentication
		} = {},
	): Promise<{ url: string; pkce: PkceChallenge }> {
		const pkce = await generatePkce(options.nsec);
		this.pendingPkce = pkce;
		// Persist PKCE to storage (survives page reload during OAuth redirect)
		this.storage.setItem(STORAGE_KEY_PKCE, JSON.stringify(pkce));

		// Generate state for multi-device email verification polling
		const state = crypto.randomUUID();
		this.storage.setItem(STORAGE_KEY_STATE, state);

		const url = new URL(`${this.config.serverUrl}/api/oauth/authorize`);
		url.searchParams.set("client_id", this.config.clientId);
		url.searchParams.set("redirect_uri", this.config.redirectUri);
		url.searchParams.set("scope", options.scopes?.join(" ") ?? "policy:full");
		url.searchParams.set("code_challenge", pkce.challenge);
		url.searchParams.set("code_challenge_method", "S256");
		url.searchParams.set("state", state);

		if (options.defaultRegister) {
			url.searchParams.set("default_register", "true");
		}

		// Use provided handle, or auto-load from storage for silent re-authentication
		const handle = options.authorizationHandle ?? this.getAuthorizationHandle();
		if (handle) {
			url.searchParams.set("authorization_handle", handle);
		}

		// Derive pubkey from nsec if provided (BYOK flow)
		if (options.nsec) {
			const pubkey = await derivePublicKeyFromNsec(options.nsec);
			url.searchParams.set("byok_pubkey", pubkey);
		}

		return { url: url.toString(), pkce };
	}

	/**
	 * Exchange authorization code for tokens
	 * Automatically saves session to storage after successful exchange
	 *
	 * @param code - Authorization code from callback
	 * @param verifier - PKCE verifier (optional if stored from getAuthorizationUrl)
	 * @returns Token response with bunker_url and optional access_token
	 */
	async exchangeCode(code: string, verifier?: string): Promise<TokenResponse> {
		// Try: explicit verifier > in-memory PKCE > stored PKCE
		let codeVerifier = verifier ?? this.pendingPkce?.verifier;
		if (!codeVerifier) {
			const storedPkce = this.storage.getItem(STORAGE_KEY_PKCE);
			if (storedPkce) {
				try {
					const parsed = JSON.parse(storedPkce) as PkceChallenge;
					codeVerifier = parsed.verifier;
				} catch {
					// Invalid stored PKCE, ignore
				}
			}
		}

		if (!codeVerifier) {
			throw new Error(
				"Session not found. This can happen if you opened this link on a different device or browser than where you started sign-in. Please return to your original device, or start a new sign-in from this one.",
			);
		}

		const response = await this.fetch(
			`${this.config.serverUrl}/api/oauth/token`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "authorization_code",
					code,
					client_id: this.config.clientId,
					redirect_uri: this.config.redirectUri,
					code_verifier: codeVerifier,
				}),
			},
		);

		const data = await response.json();

		if (!response.ok) {
			const error = data as OAuthError;
			throw new Error(
				error.error_description ?? error.error ?? "Token exchange failed",
			);
		}

		// Clear PKCE and state after successful exchange (both memory and storage)
		this.pendingPkce = null;
		this.storage.removeItem(STORAGE_KEY_PKCE);
		this.storage.removeItem(STORAGE_KEY_STATE);

		const tokenResponse = data as TokenResponse;

		// Auto-save session and authorization handle to storage
		const credentials = this.toStoredCredentials(tokenResponse);
		this.saveSession(credentials);

		return tokenResponse;
	}

	/**
	 * Parse callback URL and extract authorization code
	 *
	 * @param url - Callback URL (window.location.href)
	 * @returns Authorization code or error
	 */
	parseCallback(
		url: string,
	): { code: string } | { error: string; description?: string } {
		const parsed = new URL(url);
		const code = parsed.searchParams.get("code");
		const error = parsed.searchParams.get("error");

		if (error) {
			return {
				error,
				description: parsed.searchParams.get("error_description") ?? undefined,
			};
		}

		if (code) {
			return { code };
		}

		return {
			error: "missing_code",
			description: "No authorization code in callback URL",
		};
	}

	/**
	 * Convert TokenResponse to StoredCredentials
	 */
	toStoredCredentials(response: TokenResponse): StoredCredentials {
		const expiresAt =
			response.expires_in > 0
				? Date.now() + response.expires_in * 1000
				: undefined;

		return {
			bunkerUrl: response.bunker_url,
			accessToken: response.access_token,
			expiresAt,
			authorizationHandle: response.authorization_handle,
			refreshToken: response.refresh_token,
		};
	}

	/**
	 * Check if stored credentials are expired
	 */
	isExpired(credentials: StoredCredentials): boolean {
		if (!credentials.expiresAt) return false;
		return Date.now() >= credentials.expiresAt;
	}

	/**
	 * Check if credentials should be refreshed (expired or within 5 minutes of expiry)
	 */
	private shouldRefresh(credentials: StoredCredentials): boolean {
		if (!credentials.expiresAt) return false;
		const fiveMinutes = 5 * 60 * 1000;
		return Date.now() >= credentials.expiresAt - fiveMinutes;
	}

	/**
	 * Refresh session using stored refresh token
	 *
	 * @param refreshToken - Refresh token from previous session
	 * @returns New credentials with fresh access token and new refresh token
	 */
	async refreshSession(refreshToken: string): Promise<StoredCredentials> {
		const response = await this.fetch(
			`${this.config.serverUrl}/api/oauth/token`,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					grant_type: "refresh_token",
					refresh_token: refreshToken,
					client_id: this.config.clientId,
				}),
			},
		);

		const data = await response.json();

		if (!response.ok) {
			const error = data as OAuthError;
			throw new Error(
				error.error_description ?? error.error ?? "Token refresh failed",
			);
		}

		const tokenResponse = data as TokenResponse;
		const credentials = this.toStoredCredentials(tokenResponse);
		this.saveSession(credentials);

		return credentials;
	}
}
