# @divinevideo/login

TypeScript/JavaScript OAuth client for [Divine](https://divine.video) authentication and Nostr signing. It runs the OAuth 2.0 + PKCE authorization flow against a Divine login server, manages session storage and token refresh, and exposes a low-latency REST RPC client that mirrors NIP-46 signing methods without a relay round trip.

## Install

```bash
npm install @divinevideo/login
```

`nostr-tools` is an optional peer dependency. Install it only if you use the BYOK (bring your own key) flow, which derives a public key from an `nsec`:

```bash
npm install nostr-tools
```

The package ships ESM, CommonJS, and IIFE (browser global) builds with TypeScript declarations.

## Quick start

```typescript
import { createDivineClient } from '@divinevideo/login';

const client = createDivineClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'my-app',
  redirectUri: window.location.origin + '/callback',
  storage: localStorage, // persist the session and PKCE verifier across reloads
});

// 1. Start the OAuth flow and redirect the browser to the login server.
const { url } = await client.oauth.getAuthorizationUrl();
window.location.href = url;

// 2. Back on your redirect URI, parse the callback and exchange the code.
const result = client.oauth.parseCallback(window.location.href);
if ('code' in result) {
  const tokens = await client.oauth.exchangeCode(result.code);

  // 3. If an access token was issued, use the RPC client to sign events.
  const rpc = client.createRpc(tokens);
  if (rpc) {
    const pubkey = await rpc.getPublicKey();
    const signed = await rpc.signEvent({
      kind: 1,
      content: 'Hello from Divine!',
      tags: [],
      created_at: Math.floor(Date.now() / 1000),
      // pubkey is filled in automatically when omitted
    });
  }
}
```

When `storage` is provided, `getAuthorizationUrl()` persists the PKCE verifier so `exchangeCode(code)` can complete after a full-page redirect. Without storage, pass the verifier explicitly: `exchangeCode(code, pkce.verifier)` using the `pkce` returned from `getAuthorizationUrl()`.

## Features

- **OAuth 2.0 + PKCE** — authorization-code flow with automatic S256 PKCE generation and verification.
- **REST RPC signing** — a low-latency alternative to NIP-46 relay-based signing; the method surface mirrors NIP-46.
- **Session management** — automatic token storage, expiry-aware refresh, and silent re-authentication via an authorization handle.
- **Resilient RPC** — 429 retry with exponential backoff and `Retry-After` support, 30s request timeouts, and an `onUnauthorized` hook that transparently refreshes an expired token and retries.
- **Cross-tab safe** — concurrent refreshes are collapsed within an instance and serialized across same-origin tabs with the Web Locks API when available.
- **BYOK** — import an existing `nsec` key.
- **Pluggable** — swap the storage backend and `fetch` implementation; works with `localStorage`, `sessionStorage`, or a custom store.

## Usage

### Create a client

```typescript
import { createDivineClient } from '@divinevideo/login';

const client = createDivineClient({
  serverUrl: 'https://login.divine.video', // Divine login server
  clientId: 'my-app',                       // your OAuth client ID
  redirectUri: 'https://my-app.example/callback',
  storage: localStorage,                    // optional; defaults to in-memory
  fetch: window.fetch,                      // optional custom fetch
});
```

`createDivineClient` returns `{ oauth, createRpc }`. `oauth` is a `DivineOAuth` instance; `createRpc(tokens)` builds a `DivineRpc` from a token response, or returns `null` when the response has no `access_token`.

### Silent re-authentication

After a successful `exchangeCode`, the server may return an `authorization_handle`, which is stored automatically. Subsequent calls to `getAuthorizationUrl()` reuse it to re-authenticate without a fresh user prompt. Pass `authorizationHandle` in the options to override the stored one.

### Keeping the RPC token fresh

Wire `getSessionWithRefresh()` into the RPC client's `onUnauthorized` hook so an expired access token is refreshed and the request retried transparently:

```typescript
import { DivineRpc } from '@divinevideo/login';

const rpc = new DivineRpc({
  nostrApi: 'https://login.divine.video/api/nostr',
  accessToken: tokens.access_token!,
  onUnauthorized: async () => {
    const session = await client.oauth.getSessionWithRefresh();
    if (!session?.accessToken) throw new Error('Session expired');
    return session.accessToken;
  },
});
```

On a 401 the hook runs once, updates the bearer token, and retries. Concurrent 401s are coalesced into a single refresh.

### BYOK (bring your own key)

```typescript
const { url } = await client.oauth.getAuthorizationUrl({
  nsec: 'nsec1...',       // pubkey is derived automatically via nostr-tools
  defaultRegister: true,
});
```

## API reference

### `createDivineClient(config): { oauth, createRpc }`

Factory that pairs a `DivineOAuth` instance with a `createRpc` helper. `config` is a `DivineClientConfig`:

| Field | Type | Notes |
| --- | --- | --- |
| `serverUrl` | `string` | Divine login server, e.g. `https://login.divine.video`. |
| `clientId` | `string` | Your OAuth client ID. |
| `redirectUri` | `string` | OAuth callback URL. |
| `storage` | `DivineStorage` | Optional. Defaults to an in-memory store. |
| `fetch` | `typeof fetch` | Optional custom fetch. |

`createRpc(tokens)` returns a `DivineRpc` or `null` (when `tokens.access_token` is absent).

### `DivineOAuth`

- `getAuthorizationUrl(options?)` — build the authorization URL. Returns `{ url, pkce }`. Options: `scopes?` (defaults to `policy:full`), `nsec?` (BYOK), `defaultRegister?`, `authorizationHandle?`.
- `exchangeCode(code, verifier?)` — exchange an authorization code for a `TokenResponse` and save the session. The verifier is optional when a stored/in-memory PKCE verifier is available.
- `parseCallback(url)` — extract the code from a callback URL. Returns `{ code }` or `{ error, description? }`.
- `getSession()` — read the stored session synchronously (no refresh). Returns `StoredCredentials | null`.
- `getSessionWithRefresh()` — read the session and refresh it if expired or within five minutes of expiry. Returns `Promise<StoredCredentials | null>`.
- `refreshSession(refreshToken)` — refresh explicitly; saves and returns the rotated credentials.
- `getAuthorizationHandle()` — the stored handle for silent re-auth, if any.
- `isExpired(credentials)` — whether stored credentials are past expiry.
- `toStoredCredentials(response)` — map a `TokenResponse` to `StoredCredentials`.
- `logout()` — clear the session, authorization handle, and PKCE state.

### `DivineRpc`

Constructor options: `nostrApi` (the `/api/nostr` endpoint), `accessToken`, optional `fetch`, and optional `onUnauthorized`. Methods mirror NIP-46:

- `getPublicKey()` — the user's hex public key (cached after the first call).
- `signEvent(event)` — sign an unsigned event; `pubkey` is filled from `getPublicKey()` when omitted.
- `nip44Encrypt(pubkey, plaintext)` / `nip44Decrypt(pubkey, ciphertext)`
- `nip04Encrypt(pubkey, plaintext)` / `nip04Decrypt(pubkey, ciphertext)` — legacy.
- `DivineRpc.fromServerUrl(serverUrl, accessToken)` — static helper that derives the `/api/nostr` endpoint from a server URL.

Requests retry up to three times on HTTP 429 (honoring `Retry-After`) and time out after 30 seconds. A failed request throws `RpcError`, which carries the HTTP `status`.

### PKCE utilities

- `generatePkce(nsec?)` — generate a `{ verifier, challenge }` pair (S256).
- `validatePkce(verifier, challenge, method?)` — verify a challenge (`S256` by default).

### Types

`DivineClientConfig`, `DivineStorage`, `TokenResponse`, `StoredCredentials`, `UnsignedEvent`, `SignedEvent`, `RpcRequest`, `RpcResponse`, `PkceChallenge`, and `OAuthError` are exported for consumers.

## Configuration notes

- **Storage.** Any object implementing `getItem`/`setItem`/`removeItem` works. Session, authorization handle, PKCE verifier, and OAuth state are stored under `divine_*` keys.
- **Scopes.** `getAuthorizationUrl` defaults to the `policy:full` scope; override with `options.scopes`.
- **Token response.** `TokenResponse` always includes a `bunker_url` (NIP-46 bunker for remote signing); `access_token`, `refresh_token`, `authorization_handle`, and `scope` are present when granted.

## Browser (CDN) usage

The IIFE build exposes a `DivineLogin` global and is served from unpkg and jsDelivr:

```html
<script src="https://unpkg.com/@divinevideo/login/dist/index.global.js"></script>
<script>
  const client = DivineLogin.createDivineClient({
    serverUrl: 'https://login.divine.video',
    clientId: 'my-app',
    redirectUri: window.location.origin + '/callback',
  });
</script>
```

Bundlers can also import the browser build directly via the `@divinevideo/login/browser` export.

## Migration from keycast-login

This package is the successor to `keycast-login`. Backward-compatible aliases keep old imports working:

```typescript
// Old (still works)
import { createKeycastClient, KeycastOAuth, KeycastRpc } from '@divinevideo/login';

// New (preferred)
import { createDivineClient, DivineOAuth, DivineRpc } from '@divinevideo/login';
```

Storage keys changed from `keycast_*` to `divine_*`, so existing sessions need to re-authenticate.

## Development

```bash
npm install
npm run build        # bundle CJS, ESM, and IIFE with type declarations (tsup)
npm run dev          # watch build
npm run lint         # Biome checks on src/
npm test             # Vitest run
npm run test:watch   # Vitest watch mode
```

Continuous integration runs lint, tests, and the build on Node 22.

## License

MIT

---

Part of [Divine](https://divine.video) — your playground for human creativity · [Brand guidelines](https://github.com/divinevideo/brand-guidelines)
