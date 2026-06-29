# Cross-service contract: keycast refresh-token rotation

**Status:** active dependency · **Tracking issue:** [divine-login#8](https://github.com/divinevideo/divine-login/issues/8) · **Origin:** follow-up to PR #6 (issue #5)

This document records a behavior of the keycast auth server that `@divinevideo/login`
silently depends on. Nothing in this repo's test suite will fail if keycast breaks
the contract, so this doc plus the `CONTRACT:` anchor in `src/oauth.ts` are the
tripwire: a human reviewing a keycast auth change should find this contract before
shipping.

## The contract in one sentence

> When two callers refresh the same session concurrently, exactly one rotation wins;
> presenting the *losing* (already-consumed) refresh token must fail closed with
> `invalid_grant` and **must not revoke the authorization's token family** — the
> winner's freshly-rotated refresh token stays valid server-side.

## Where divine-login depends on it

`src/oauth.ts` → `getSessionWithRefresh()` → `refreshIfNeeded()`.

When a refresh POST fails, `refreshIfNeeded()` does **not** wipe the session. It
re-reads storage and, if storage now holds a *different* refresh token, concludes a
sibling tab/instance won the rotation race and returns that sibling's session
(see the catch block, the comment ending "the winner's rotated token stays valid
server-side"). That recovery is only safe because the failed POST of the
already-consumed token did **not** invalidate the winner's new token.

Note the sequencing: the losing caller **POSTs the consumed refresh token to keycast**
before the re-read. That POST — presenting a consumed refresh token — is exactly the
event refresh-token *reuse detection* keys on.

## Why it matters (failure mode if the contract breaks)

If keycast adds reuse detection (treats a consumed-token replay as a compromise
signal and revokes the active token — commonly the whole token family — as
RFC 9700 §4.14.2 recommends), then:

1. The loser POSTs the consumed token.
2. keycast revokes every refresh token for that authorization — **including the
   winner's freshly-rotated token.**
3. The loser's re-read returns the winner's session, but its refresh token is now
   revoked server-side.
4. The next refresh fails with `invalid_grant` → the user is silently logged out.

So under reuse detection the recovery would hand back a doomed session, and on the
no-lock fallback path a single concurrent refresh would log out *both* tabs, not just
defeat the recovery. This is invisible from the divine-login side — the only symptom
is users getting logged out again, the exact regression PR #6 fixed.

## Scope: which path actually replays a consumed token

- **Web Locks happy path:** cross-tab refreshes are serialized. The second tab
  acquires the lock, re-reads storage, sees the fresh token (`shouldRefresh` is
  false) and returns **without POSTing**. No consumed token is replayed, so reuse
  detection would not even fire here.
- **No-Web-Locks fallback path** (non-browser runtimes, older browsers, or a rejected
  lock request) and the cross-process window tracked by
  [divine-login#7](https://github.com/divinevideo/divine-login/issues/7): two callers
  can interleave, both POST, and the loser replays the consumed token. **This is the
  path that depends on the contract.**

## Verification — current keycast behaves correctly

Verified against `divinevideo/keycast` @ `c235095` (the assumption holds today).
The three cited files are byte-identical from `c235095` through current keycast
`main` HEAD `a4d59f1` (and through `c828851`), so the table below needs no re-diff
against those revisions:

| Fact | Location |
| --- | --- |
| `consume()` is an atomic single-use `UPDATE ... SET consumed_at = NOW() WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > NOW() RETURNING *`; one concurrent caller wins, losers get `None`. | `core/src/repositories/refresh_token.rs` (`consume`) |
| The refresh-token grant handler returns `invalid_grant` on `None` and **does not** call `revoke_for_authorization`. The winner's new token (created in the winner's own handler invocation) survives. | `api/src/api/http/oauth.rs` (refresh_token grant) |
| The family-revoke primitive `revoke_for_authorization()` exists but is wired **only** to re-authorization cleanup, not to reuse detection. | `core/src/repositories/refresh_token.rs` (`revoke_for_authorization`); call site in `api/src/api/http/oauth.rs` |
| No reuse-detection code, `TODO`, or doc item; no open keycast issue for it. keycast's own doc documents one-time-use replay → `invalid_grant` only. | `docs/SILENT_REAUTH_IMPLEMENTATION.md` |

## Why this is fragile (not paranoia)

- The family-revoke primitive (`revoke_for_authorization`) already exists — reuse
  detection is roughly one call added to the `consume() == None` branch.
- keycast explicitly cites **RFC 9700** (OAuth 2.0 Security BCP) for its rotation.
  RFC 9700 §4.14.2 *recommends* that on detecting refresh-token reuse the authorization
  server SHOULD revoke the active refresh token. (Revoking the whole token family is a
  common implementation of that guidance, not the RFC's literal text.) keycast
  implements the rotation half of that recommendation but not the revoke-on-reuse
  half — so adopting reuse detection would be a natural, standards-endorsed future
  change.

## Required follow-ups (human action — cannot be automated from this repo)

1. **Confirm with the keycast owners** whether refresh-token reuse detection is on the
   roadmap. (Acceptance criterion #1 for issue #8. As of `c235095` it is not
   implemented and not tracked, but owner confirmation needs a person.)
2. **Mirror this contract into keycast so both services can see it:**
   - Add the contract statement to keycast `docs/SILENT_REAUTH_IMPLEMENTATION.md`
     (Security Considerations), e.g. *"Replaying a consumed refresh token returns
     `invalid_grant` and does NOT revoke other tokens for the authorization;
     concurrent rotation must not revoke the winner. Clients (divine-login) rely on
     this for concurrent-refresh recovery — see divine-login#8."*
   - Add a keycast regression test that asserts: after token A is rotated to token B,
     replaying token A returns `invalid_grant` **and token B still refreshes
     successfully**. That test is the only place an automated CI tripwire can actually
     fire, because nothing in divine-login breaks when keycast changes.

## Fallback if reuse detection *is* adopted

If keycast confirms reuse detection is planned, the recovery in `refreshIfNeeded()`
must change rather than rely on the re-read. Options, cheapest first:

1. **Rely solely on Web Locks serialization** and drop the fallback-path re-read
   recovery, accepting that non-lock environments may log out on concurrent refresh
   (couple with issue #7's cross-process hardening).
2. **Re-validate on recovery:** before returning the sibling-rotated session, make a
   cheap authenticated call to confirm the re-read token is still live; only return it
   if valid. Adds one request on the rare recovery path.
3. **Coordinate a keycast carve-out** so legitimate concurrent rotation is not treated
   as reuse (e.g. a short grace window where the immediately-prior token's replay is a
   no-op rather than a family-revoke).
