# @divinevideo/login

TypeScript/JavaScript OAuth client for [Divine](https://divine.video) authentication and Nostr signing via REST RPC.

## Install

```bash
npm install @divinevideo/login
```

## Quick Start

```typescript
import { createDivineClient } from '@divinevideo/login';

const client = createDivineClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'my-app',
  redirectUri: window.location.origin + '/callback',
  storage: localStorage, // persist sessions across page reloads
});

// Start OAuth flow
const { url } = await client.oauth.getAuthorizationUrl();
window.location.href = url;

// After redirect back, exchange code for tokens
const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const tokens = await client.oauth.exchangeCode(code);

// Use RPC client for Nostr signing
const rpc = client.createRpc(tokens);
const pubkey = await rpc.getPublicKey();
const signed = await rpc.signEvent({
  kind: 1,
  content: 'Hello from Divine!',
  tags: [],
  created_at: Math.floor(Date.now() / 1000),
  pubkey,
});
```

## Features

- **OAuth 2.0 + PKCE** — Secure authorization flow with automatic PKCE handling
- **REST RPC signing** — Low-latency alternative to NIP-46 relay-based signing
- **Session management** — Automatic token storage, refresh, and silent re-authentication
- **BYOK (Bring Your Own Key)** — Import existing nsec keys
- **Storage abstraction** — Works with localStorage, sessionStorage, or custom backends
- **Tree-shakeable** — ESM, CJS, and IIFE (browser global) builds

## API

### `createDivineClient(config)`

Creates a client with OAuth and RPC capabilities.

```typescript
const client = createDivineClient({
  serverUrl: string;     // e.g., "https://login.divine.video"
  clientId: string;      // Your app's OAuth client ID
  redirectUri: string;   // OAuth callback URL
  storage?: Storage;     // Optional storage backend (default: in-memory)
  fetch?: typeof fetch;  // Optional custom fetch
});
```

### `client.oauth`

- `getAuthorizationUrl(options?)` — Generate OAuth URL with PKCE
- `exchangeCode(code, verifier?)` — Exchange auth code for tokens
- `parseCallback(url)` — Extract code from callback URL
- `getSession()` — Get stored credentials (sync)
- `getSessionWithRefresh()` — Get credentials with auto-refresh
- `logout()` — Clear all session data
- `refreshSession(refreshToken)` — Manually refresh tokens

### `client.createRpc(tokens)`

Creates a Nostr RPC client (mirrors NIP-46 methods):

- `getPublicKey()` — Get user's hex pubkey
- `signEvent(event)` — Sign an unsigned Nostr event
- `nip44Encrypt(pubkey, plaintext)` / `nip44Decrypt(pubkey, ciphertext)`
- `nip04Encrypt(pubkey, plaintext)` / `nip04Decrypt(pubkey, ciphertext)`

## BYOK (Bring Your Own Key)

```typescript
const { url } = await client.oauth.getAuthorizationUrl({
  nsec: 'nsec1...', // User's existing key (pubkey derived automatically)
  defaultRegister: true,
});
```

## Migration from keycast-login

This package is the successor to `keycast-login`. Backward-compatible aliases are provided:

```typescript
// Old (still works)
import { createKeycastClient, KeycastOAuth, KeycastRpc } from '@divinevideo/login';

// New (preferred)
import { createDivineClient, DivineOAuth, DivineRpc } from '@divinevideo/login';
```

Storage keys changed from `keycast_*` to `divine_*`. Existing sessions will need to re-authenticate.

## License

MIT
