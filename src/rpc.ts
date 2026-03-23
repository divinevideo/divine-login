// ABOUTME: RPC client for Divine Nostr API
// ABOUTME: Low-latency alternative to NIP-46 relay-based signing

import { RpcError } from './types';
import type { RpcResponse, SignedEvent, UnsignedEvent } from './types';

/**
 * RPC client for Divine Nostr API
 *
 * Provides a low-latency REST alternative to NIP-46 relay-based signing.
 * Mirrors the NIP-46 method signatures for easy migration.
 */
export class DivineRpc {
  private nostrApi: string;
  private accessToken: string;
  private fetch: typeof globalThis.fetch;
  private cachedPubkey: string | null = null;

  constructor(options: {
    nostrApi: string;
    accessToken: string;
    fetch?: typeof fetch;
  }) {
    this.nostrApi = options.nostrApi;
    this.accessToken = options.accessToken;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * Make an RPC call to the API
   */
  private async call<T>(method: string, params: unknown[] = []): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const response = await this.fetch(this.nostrApi, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify({ method, params }),
        signal: AbortSignal.timeout(30_000),
      });

      if (response.status === 429 && attempt < 3) {
        const retryAfter = response.headers?.get?.('Retry-After');
        const delay = retryAfter ? Number(retryAfter) * 1000 : 1000 * 2 ** attempt;
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      if (!response.ok) throw new RpcError(response.status);

      const data: RpcResponse<T> = await response.json();

      if (data.error) {
        throw new Error(data.error);
      }

      if (data.result === undefined) {
        throw new Error('No result in RPC response');
      }

      return data.result;
    }
  }

  /**
   * Get the user's public key (hex format)
   *
   * Mirrors NIP-46 get_public_key method
   */
  async getPublicKey(): Promise<string> {
    if (this.cachedPubkey) return this.cachedPubkey;
    const pubkey = await this.call<string>('get_public_key', []);
    this.cachedPubkey = pubkey;
    return pubkey;
  }

  /**
   * Sign an unsigned Nostr event
   *
   * Mirrors NIP-46 sign_event method
   *
   * @param event - Unsigned event to sign
   * @returns Signed event with id and sig
   */
  async signEvent(event: UnsignedEvent): Promise<SignedEvent> {
    return this.call<SignedEvent>('sign_event', [event]);
  }

  /**
   * Encrypt plaintext using NIP-44
   */
  async nip44Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.call<string>('nip44_encrypt', [recipientPubkey, plaintext]);
  }

  /**
   * Decrypt ciphertext using NIP-44
   */
  async nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.call<string>('nip44_decrypt', [senderPubkey, ciphertext]);
  }

  /**
   * Encrypt plaintext using NIP-04 (legacy)
   */
  async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.call<string>('nip04_encrypt', [recipientPubkey, plaintext]);
  }

  /**
   * Decrypt ciphertext using NIP-04 (legacy)
   */
  async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.call<string>('nip04_decrypt', [senderPubkey, ciphertext]);
  }

  /**
   * Create a new RPC client from server URL and access token
   */
  static fromServerUrl(serverUrl: string, accessToken: string): DivineRpc {
    return new DivineRpc({
      nostrApi: `${serverUrl}/api/nostr`,
      accessToken,
    });
  }
}
