import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DivineOAuth } from '../src/oauth';

describe('DivineOAuth', () => {
  const config = {
    serverUrl: 'https://login.divine.video',
    clientId: 'test-app',
    redirectUri: 'http://localhost:3000/callback',
  };

  describe('getAuthorizationUrl', () => {
    it('should generate valid authorization URL', async () => {
      const oauth = new DivineOAuth(config);
      const { url, pkce } = await oauth.getAuthorizationUrl();

      expect(url).toContain(config.serverUrl);
      expect(url).toContain('client_id=test-app');
      expect(url).toContain('redirect_uri=');
      expect(url).toContain('code_challenge=');
      expect(url).toContain('code_challenge_method=S256');
      expect(pkce.verifier).toBeDefined();
      expect(pkce.challenge).toBeDefined();
    });

    it('should include custom scopes', async () => {
      const oauth = new DivineOAuth(config);
      const { url } = await oauth.getAuthorizationUrl({
        scopes: ['sign_event', 'encrypt'],
      });

      expect(url).toContain('scope=sign_event+encrypt');
    });

    it('should include BYOK parameters when nsec provided', async () => {
      // Note: This test requires nostr-tools to be installed
      // The nsec below is a test vector, not a real key
      const testNsec = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';
      const expectedPubkey = '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e';

      const oauth = new DivineOAuth(config);
      const { url, pkce } = await oauth.getAuthorizationUrl({
        nsec: testNsec,
        defaultRegister: true,
      });

      expect(url).toContain(`byok_pubkey=${expectedPubkey}`);
      expect(url).toContain('default_register=true');
      expect(pkce.verifier).toContain(testNsec);
    });
  });

  describe('parseCallback', () => {
    it('should parse authorization code', () => {
      const oauth = new DivineOAuth(config);
      const result = oauth.parseCallback(
        'http://localhost:3000/callback?code=abc123'
      );

      expect(result).toEqual({ code: 'abc123' });
    });

    it('should parse error', () => {
      const oauth = new DivineOAuth(config);
      const result = oauth.parseCallback(
        'http://localhost:3000/callback?error=access_denied&error_description=User%20denied'
      );

      expect(result).toEqual({
        error: 'access_denied',
        description: 'User denied',
      });
    });

    it('should return error for missing code', () => {
      const oauth = new DivineOAuth(config);
      const result = oauth.parseCallback('http://localhost:3000/callback');

      expect('error' in result).toBe(true);
    });
  });

  describe('exchangeCode', () => {
    it('should exchange code for tokens', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            bunker_url: 'bunker://abc?relay=wss://relay.test&secret=xyz',
            access_token: 'ucan_token',
            token_type: 'Bearer',
            expires_in: 86400,
            scope: 'sign_event',
          }),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any });

      // Generate URL first to store PKCE
      await oauth.getAuthorizationUrl();

      const tokens = await oauth.exchangeCode('test_code');

      expect(tokens.bunker_url).toBeDefined();
      expect(tokens.access_token).toBe('ucan_token');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://login.divine.video/api/oauth/token',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        })
      );
    });

    it('should throw on error response', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        json: () =>
          Promise.resolve({
            error: 'invalid_grant',
            error_description: 'Code expired',
          }),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any });
      await oauth.getAuthorizationUrl();

      await expect(oauth.exchangeCode('expired_code')).rejects.toThrow(
        'Code expired'
      );
    });

    it('should throw if no PKCE verifier', async () => {
      const oauth = new DivineOAuth(config);

      await expect(oauth.exchangeCode('code')).rejects.toThrow(
        'Session not found'
      );
    });
  });

  describe('toStoredCredentials', () => {
    it('should convert token response', () => {
      const oauth = new DivineOAuth(config);
      const response = {
        bunker_url: 'bunker://abc',
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'sign_event',
      };

      const credentials = oauth.toStoredCredentials(response);

      expect(credentials.bunkerUrl).toBe('bunker://abc');
      expect(credentials.accessToken).toBe('token');
      expect(credentials.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should handle zero expiry', () => {
      const oauth = new DivineOAuth(config);
      const response = {
        bunker_url: 'bunker://abc',
        token_type: 'Bearer',
        expires_in: 0,
      };

      const credentials = oauth.toStoredCredentials(response);

      expect(credentials.expiresAt).toBeUndefined();
    });
  });

  describe('isExpired', () => {
    it('should return false for non-expired credentials', () => {
      const oauth = new DivineOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
        expiresAt: Date.now() + 3600000,
      };

      expect(oauth.isExpired(credentials)).toBe(false);
    });

    it('should return true for expired credentials', () => {
      const oauth = new DivineOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
        expiresAt: Date.now() - 1000,
      };

      expect(oauth.isExpired(credentials)).toBe(true);
    });

    it('should return false for credentials without expiry', () => {
      const oauth = new DivineOAuth(config);
      const credentials = {
        bunkerUrl: 'bunker://abc',
      };

      expect(oauth.isExpired(credentials)).toBe(false);
    });
  });

  describe('toStoredCredentials with refresh_token', () => {
    it('should store refresh_token', () => {
      const oauth = new DivineOAuth(config);
      const response = {
        bunker_url: 'bunker://abc',
        access_token: 'token',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'refresh123',
      };

      const credentials = oauth.toStoredCredentials(response);

      expect(credentials.refreshToken).toBe('refresh123');
    });
  });

  describe('getSessionWithRefresh', () => {
    it('should return null if no session', async () => {
      const oauth = new DivineOAuth(config);
      const result = await oauth.getSessionWithRefresh();
      expect(result).toBeNull();
    });

    it('should return credentials if not near expiry', async () => {
      const storage = new Map<string, string>();
      const oauth = new DivineOAuth({
        ...config,
        storage: {
          getItem: (k) => storage.get(k) ?? null,
          setItem: (k, v) => storage.set(k, v),
          removeItem: (k) => storage.delete(k),
        },
      });

      const credentials = {
        bunkerUrl: 'bunker://abc',
        accessToken: 'token',
        expiresAt: Date.now() + 3600000, // 1 hour from now
      };
      storage.set('divine_session', JSON.stringify(credentials));

      const result = await oauth.getSessionWithRefresh();
      expect(result?.bunkerUrl).toBe('bunker://abc');
    });

    it('should return null if expired and no refresh token', async () => {
      const storage = new Map<string, string>();
      const oauth = new DivineOAuth({
        ...config,
        storage: {
          getItem: (k) => storage.get(k) ?? null,
          setItem: (k, v) => storage.set(k, v),
          removeItem: (k) => storage.delete(k),
        },
      });

      const credentials = {
        bunkerUrl: 'bunker://abc',
        accessToken: 'token',
        expiresAt: Date.now() - 1000, // expired
      };
      storage.set('divine_session', JSON.stringify(credentials));

      const result = await oauth.getSessionWithRefresh();
      expect(result).toBeNull();
    });
  });

  describe('getSessionWithRefresh — concurrent rotation', () => {
    // The failure path intentionally logs via console.warn; silence it so test
    // output stays clean, and keep the spy so tests can assert it fired.
    let warnSpy: ReturnType<typeof vi.spyOn>;
    beforeEach(() => {
      warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      // Default to the no-Web-Locks fallback so behavior does not depend on
      // whether the runtime ships navigator.locks (modern Node and browsers do).
      // The cross-tab serialization test opts in with its own serializing stub.
      vi.stubGlobal('navigator', {});
    });
    afterEach(() => {
      warnSpy.mockRestore();
      vi.unstubAllGlobals();
    });

    // Build a Map-backed storage shared between OAuth instances to model two
    // browser tabs (or two module instances) sharing the same localStorage.
    function sharedStorage() {
      const store = new Map<string, string>();
      return {
        store,
        storage: {
          getItem: (k: string) => store.get(k) ?? null,
          setItem: (k: string, v: string) => {
            store.set(k, v);
          },
          removeItem: (k: string) => {
            store.delete(k);
          },
        },
      };
    }

    // Minimal Web Locks stand-in: exclusive and FIFO per lock name. Each request
    // for a name runs its callback only after the previous holder's callback
    // settles — enough to model navigator.locks serializing two tabs.
    function serializingLockManager() {
      const chains = new Map<string, Promise<unknown>>();
      return {
        request(name: string, callback: (lock: unknown) => unknown) {
          const prev = chains.get(name) ?? Promise.resolve();
          const run = prev.then(() => callback({ name }));
          chains.set(
            name,
            run.then(
              () => {},
              () => {}
            )
          );
          return run;
        },
      };
    }

    const nearExpirySession = {
      bunkerUrl: 'bunker://old',
      accessToken: 'A0',
      refreshToken: 'R0',
      expiresAt: Date.now() + 60_000, // inside the 5-minute refresh window
    };

    it('recovers the winner session for the loser instead of wiping it', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // Model keycast's single-use rotation: the first POST wins with a rotated
      // token, every later replay of R0 gets HTTP 400 invalid_grant.
      let callCount = 0;
      const mockFetch = vi.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve({
                bunker_url: 'bunker://new',
                access_token: 'A1',
                token_type: 'Bearer',
                expires_in: 86400,
                refresh_token: 'R1',
              }),
          });
        }
        return Promise.resolve({
          ok: false,
          status: 400,
          json: () =>
            Promise.resolve({
              error: 'invalid_grant',
              error_description: 'refresh token already used',
            }),
        });
      });

      const oauthA = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });
      const oauthB = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const [resA, resB] = await Promise.all([
        oauthA.getSessionWithRefresh(),
        oauthB.getSessionWithRefresh(),
      ]);

      // Both callers end with the winner's valid rotated credentials.
      expect(resA).not.toBeNull();
      expect(resB).not.toBeNull();
      expect(resA?.refreshToken).toBe('R1');
      expect(resA?.accessToken).toBe('A1');
      expect(resB?.refreshToken).toBe('R1');
      expect(resB?.accessToken).toBe('A1');

      // The stored session is the winner's and was never deleted.
      expect(store.has('divine_session')).toBe(true);
      const stored = JSON.parse(store.get('divine_session') as string);
      expect(stored.refreshToken).toBe('R1');
      expect(stored.accessToken).toBe('A1');

      // One POST per instance (singleflight is per-instance, added separately).
      expect(mockFetch).toHaveBeenCalledTimes(2);
      // The loser hit the refresh-failure path before recovering.
      expect(warnSpy).toHaveBeenCalled();
    });

    it('still clears the session when the refresh token is genuinely dead', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () =>
          Promise.resolve({
            error: 'invalid_grant',
            error_description: 'refresh token expired',
          }),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      expect(result).toBeNull();
      expect(store.has('divine_session')).toBe(false);
      expect(warnSpy).toHaveBeenCalled();
    });

    it('collapses concurrent calls in one instance into a single refresh POST', async () => {
      const { storage } = sharedStorage();
      storage.setItem('divine_session', JSON.stringify(nearExpirySession));

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            bunker_url: 'bunker://new',
            access_token: 'A1',
            token_type: 'Bearer',
            expires_in: 86400,
            refresh_token: 'R1',
          }),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const results = await Promise.all([
        oauth.getSessionWithRefresh(),
        oauth.getSessionWithRefresh(),
        oauth.getSessionWithRefresh(),
      ]);

      // Concurrent callers share a single in-flight rotation POST...
      expect(mockFetch).toHaveBeenCalledTimes(1);
      // ...and all resolve to the same rotated credentials.
      for (const r of results) {
        expect(r?.refreshToken).toBe('R1');
        expect(r?.accessToken).toBe('A1');
      }
    });

    it('does not wipe the session when refresh fails transiently (network reject)', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // fetch itself rejects (offline, DNS, connection reset): the server never
      // saw the request, so the refresh token is still valid. Wiping here would
      // log the user out on a transient blip.
      const mockFetch = vi.fn().mockRejectedValue(new Error('network down'));

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      // Session is preserved and the existing credentials are returned so the
      // next call can retry.
      expect(result).not.toBeNull();
      expect(result?.refreshToken).toBe('R0');
      expect(store.has('divine_session')).toBe(true);
      const stored = JSON.parse(store.get('divine_session') as string);
      expect(stored.refreshToken).toBe('R0');
      expect(warnSpy).toHaveBeenCalled();
    });

    it('does not wipe the session on a transient 5xx with a non-JSON body', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // HTTP 503 whose body is not JSON (e.g. a proxy HTML error page). The
      // status, not the body, decides: 5xx is transient, so json() throwing must
      // not be mistaken for token death.
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        json: () => Promise.reject(new SyntaxError('Unexpected token < in JSON')),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      expect(result).not.toBeNull();
      expect(result?.refreshToken).toBe('R0');
      expect(store.has('divine_session')).toBe(true);
      expect(warnSpy).toHaveBeenCalled();
    });

    it('clears the session on a definitive HTTP 400 even when the error body is not JSON', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // HTTP 400 with a non-JSON body: json() rejects, but the 400 status is the
      // authoritative token-death signal, so the session must still be cleared.
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.reject(new SyntaxError('Unexpected token < in JSON')),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      expect(result).toBeNull();
      expect(store.has('divine_session')).toBe(false);
      expect(warnSpy).toHaveBeenCalled();
    });

    it('serializes refresh across tabs so the loser reuses the rotated session without a second POST', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // With the Web Locks API present, the two tabs must take turns: the first
      // rotates the token, the second waits, re-reads, and finds a fresh session
      // — so it never replays the consumed token.
      vi.stubGlobal('navigator', { locks: serializingLockManager() });

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            bunker_url: 'bunker://new',
            access_token: 'A1',
            token_type: 'Bearer',
            expires_in: 86400,
            refresh_token: 'R1',
          }),
      });

      const oauthA = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });
      const oauthB = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const [resA, resB] = await Promise.all([
        oauthA.getSessionWithRefresh(),
        oauthB.getSessionWithRefresh(),
      ]);

      // Only one refresh POST happened: the lock made the loser reuse the
      // winner's rotated session instead of replaying the single-use token.
      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(resA?.refreshToken).toBe('R1');
      expect(resB?.refreshToken).toBe('R1');
      expect(store.has('divine_session')).toBe(true);
      const stored = JSON.parse(store.get('divine_session') as string);
      expect(stored.refreshToken).toBe('R1');
    });

    it('bounds the refresh fetch with an abort signal so a hung refresh cannot hold the lock open', async () => {
      const { storage } = sharedStorage();
      storage.setItem('divine_session', JSON.stringify(nearExpirySession));

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            bunker_url: 'bunker://new',
            access_token: 'A1',
            token_type: 'Bearer',
            expires_in: 86400,
            refresh_token: 'R1',
          }),
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });
      await oauth.getSessionWithRefresh();

      // The refresh POST must carry a timeout AbortSignal so a stuck request
      // aborts instead of holding the cross-tab refresh lock open indefinitely.
      const init = mockFetch.mock.calls[0][1];
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(init.signal.aborted).toBe(false);
    });

    it('treats a refresh fetch abort (timeout) as transient and keeps the session', async () => {
      const { store, storage } = sharedStorage();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      // Simulate AbortSignal.timeout firing: fetch rejects with a TimeoutError.
      // The request never reached the server, so the token may still be valid —
      // this is transient and the session must be kept, not wiped.
      const mockFetch = vi
        .fn()
        .mockRejectedValue(
          new DOMException('The operation timed out.', 'TimeoutError')
        );

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      expect(result).not.toBeNull();
      expect(result?.refreshToken).toBe('R0');
      expect(store.has('divine_session')).toBe(true);
      expect(warnSpy).toHaveBeenCalled();
    });

    it('re-reads before deleting so a sibling rotation in the delete window is recovered, not wiped', async () => {
      // No Web Locks here (navigator is stubbed to {} by beforeEach), so this is
      // the fallback path. Model the narrow cross-tab race where the winner saves
      // its rotated session AFTER the loser's first post-failure re-read but
      // BEFORE the loser deletes: the compare-and-delete must observe the rotated
      // token and recover it instead of wiping the winner's fresh session.
      const winnerSession = {
        bunkerUrl: 'bunker://new',
        accessToken: 'A1',
        refreshToken: 'R1',
        expiresAt: Date.now() + 86_400_000,
      };

      const store = new Map<string, string>();
      store.set('divine_session', JSON.stringify(nearExpirySession));

      let refreshFailed = false;
      let swapped = false;
      const removeItem = vi.fn((k: string) => {
        store.delete(k);
      });
      const storage = {
        getItem: (k: string) => {
          const v = store.get(k) ?? null;
          // The first session read AFTER the refresh has failed is the loser's
          // first re-read (it still sees the dead token); land the winner's save
          // immediately after it so the next read sees the rotated session.
          if (k === 'divine_session' && refreshFailed && !swapped) {
            swapped = true;
            store.set('divine_session', JSON.stringify(winnerSession));
          }
          return v;
        },
        setItem: (k: string, v: string) => {
          store.set(k, v);
        },
        removeItem,
      };

      const mockFetch = vi.fn().mockImplementation(() => {
        refreshFailed = true;
        return Promise.resolve({
          ok: false,
          status: 400,
          json: () =>
            Promise.resolve({
              error: 'invalid_grant',
              error_description: 'refresh token already used',
            }),
        });
      });

      const oauth = new DivineOAuth({ ...config, fetch: mockFetch as any, storage });

      const result = await oauth.getSessionWithRefresh();

      // The loser recovers the winner's rotated session and never deletes it.
      expect(result?.refreshToken).toBe('R1');
      expect(result?.accessToken).toBe('A1');
      expect(removeItem).not.toHaveBeenCalled();
      expect(store.has('divine_session')).toBe(true);
      const stored = JSON.parse(store.get('divine_session') as string);
      expect(stored.refreshToken).toBe('R1');
      expect(warnSpy).toHaveBeenCalled();
    });
  });
});
