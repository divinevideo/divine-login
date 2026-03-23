import { describe, expect, it, vi } from 'vitest';
import { DivineRpc } from '../src/rpc';
import { RpcError } from '../src/types';

describe('DivineRpc', () => {
  const config = {
    nostrApi: 'https://login.divine.video/api/nostr',
    accessToken: 'test_token',
  };

  describe('getPublicKey', () => {
    it('should return public key', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            result: 'abc123def456',
          }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const pubkey = await rpc.getPublicKey();

      expect(pubkey).toBe('abc123def456');
      expect(mockFetch).toHaveBeenCalledWith(
        config.nostrApi,
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer test_token',
          }),
          body: JSON.stringify({ method: 'get_public_key', params: [] }),
        })
      );
    });

    it('should throw on error', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            error: 'Unauthorized',
          }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });

      await expect(rpc.getPublicKey()).rejects.toThrow('Unauthorized');
    });
  });

  describe('signEvent', () => {
    it('should sign event', async () => {
      const signedEvent = {
        id: 'event123',
        pubkey: 'abc123',
        kind: 1,
        content: 'Hello!',
        tags: [],
        created_at: 1234567890,
        sig: 'sig123',
      };

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: signedEvent }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const result = await rpc.signEvent({
        kind: 1,
        content: 'Hello!',
        tags: [],
        created_at: 1234567890,
        pubkey: 'abc123',
      });

      expect(result).toEqual(signedEvent);
      expect(result.id).toBe('event123');
      expect(result.sig).toBe('sig123');
    });
  });

  describe('nip44Encrypt', () => {
    it('should encrypt plaintext', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: 'encrypted_data' }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const ciphertext = await rpc.nip44Encrypt('recipient_pubkey', 'secret message');

      expect(ciphertext).toBe('encrypted_data');
      expect(mockFetch).toHaveBeenCalledWith(
        config.nostrApi,
        expect.objectContaining({
          body: JSON.stringify({
            method: 'nip44_encrypt',
            params: ['recipient_pubkey', 'secret message'],
          }),
        })
      );
    });
  });

  describe('nip44Decrypt', () => {
    it('should decrypt ciphertext', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: 'decrypted message' }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const plaintext = await rpc.nip44Decrypt('sender_pubkey', 'encrypted_data');

      expect(plaintext).toBe('decrypted message');
    });
  });

  describe('nip04Encrypt', () => {
    it('should encrypt plaintext with NIP-04', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: 'nip04_encrypted' }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const ciphertext = await rpc.nip04Encrypt('recipient_pubkey', 'secret');

      expect(ciphertext).toBe('nip04_encrypted');
    });
  });

  describe('nip04Decrypt', () => {
    it('should decrypt ciphertext with NIP-04', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: 'nip04_decrypted' }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const plaintext = await rpc.nip04Decrypt('sender_pubkey', 'encrypted');

      expect(plaintext).toBe('nip04_decrypted');
    });
  });

  describe('AbortSignal and RpcError', () => {
    it('should pass AbortSignal.timeout to fetch', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ result: 'abc123' }),
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      await rpc.getPublicKey();

      const fetchOptions = mockFetch.mock.calls[0][1];
      expect(fetchOptions.signal).toBeInstanceOf(AbortSignal);
    });

    it('should throw RpcError on HTTP 500', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });

      await expect(rpc.getPublicKey()).rejects.toThrow(RpcError);
      await expect(rpc.getPublicKey()).rejects.toThrow('RPC failed: HTTP 500');
    });

    it('should throw RpcError on HTTP 401 with correct status', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
      });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });

      try {
        await rpc.getPublicKey();
        expect.unreachable('should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(RpcError);
        expect((e as RpcError).status).toBe(401);
      }
    });
  });

  describe('429 retry', () => {
    it('should retry on 429 and succeed', async () => {
      vi.useFakeTimers();
      const mockFetch = vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: () => null },
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ result: 'abc123' }),
        });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const promise = rpc.getPublicKey();

      await vi.advanceTimersByTimeAsync(1000);
      const result = await promise;

      expect(result).toBe('abc123');
      expect(mockFetch).toHaveBeenCalledTimes(2);
      vi.useRealTimers();
    });

    it('should respect Retry-After header', async () => {
      vi.useFakeTimers();
      const mockFetch = vi.fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: { get: (h: string) => h === 'Retry-After' ? '5' : null },
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ result: 'abc123' }),
        });

      const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
      const promise = rpc.getPublicKey();

      // Should not resolve after 4s (Retry-After is 5s)
      await vi.advanceTimersByTimeAsync(4999);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(1);
      const result = await promise;
      expect(result).toBe('abc123');
      expect(mockFetch).toHaveBeenCalledTimes(2);
      vi.useRealTimers();
    });

    it('should throw RpcError(429) after 4 attempts', async () => {
      vi.useFakeTimers();
      try {
        const mockFetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 429,
          headers: { get: () => null },
        });

        const rpc = new DivineRpc({ ...config, fetch: mockFetch as any });
        let caught: unknown;
        const promise = rpc.getPublicKey().catch((e) => { caught = e; });

        // Advance through 3 retry delays: 1s, 2s, 4s
        await vi.advanceTimersByTimeAsync(1000);
        await vi.advanceTimersByTimeAsync(2000);
        await vi.advanceTimersByTimeAsync(4000);
        await promise;

        expect(caught).toBeInstanceOf(RpcError);
        expect((caught as RpcError).status).toBe(429);

        // 4 total: 1 initial + 3 retries
        expect(mockFetch).toHaveBeenCalledTimes(4);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe('fromServerUrl', () => {
    it('should create client from server URL and access token', () => {
      const rpc = DivineRpc.fromServerUrl('https://login.divine.video', 'token');

      expect(rpc).toBeInstanceOf(DivineRpc);
    });
  });
});
