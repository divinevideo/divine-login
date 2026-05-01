# Repository Guidelines

## Project Structure & Module Organization
- Library source lives in `src/`, with OAuth, PKCE, RPC, and shared types split into focused modules.
- Tests live in `tests/`.
- Package metadata and scripts live in `package.json`; TypeScript config lives in `tsconfig.json`.
- Keep new modules small and composable. Prefer clear public API boundaries over broad shared utility files.

## Build, Test, and Development Commands
- `npm install`: install dependencies.
- `npm run build`: build CJS, ESM, IIFE, and type declarations with `tsup`.
- `npm run dev`: run the watch build for local iteration.
- `npm run lint`: run Biome checks on `src/`.
- `npm test`: run the Vitest suite in CI mode.
- `npm run test:watch`: run the test suite in watch mode.

## Coding Style & Naming Conventions
- Use TypeScript throughout and keep public API types explicit.
- Prefer small modules and user-facing tests over implicit shared state or broad helper buckets.
- Keep PRs tightly scoped. Do not mix unrelated cleanup, formatting churn, or speculative refactors into the same change.
- Temporary or transitional code must include `TODO(#issue):` with the tracking issue for removal.

## Pull Request Guardrails
- PR titles must use Conventional Commit format: `type(scope): summary` or `type: summary`.
- Set the correct PR title when opening the PR. Do not rely on fixing it afterward.
- If a PR title changes after opening, verify that the semantic PR title check reruns successfully.
- PR descriptions must include a short summary, motivation, linked issue, and manual test plan.
- Changes to the public client API, storage behavior, or auth flow should include representative usage snippets or migration notes when helpful.

## Security & Sensitive Information
- Do not commit secrets, live OAuth credentials, real user tokens, or private key material.
- Public issues, PRs, branch names, screenshots, and descriptions must not mention corporate partners, customers, brands, campaign names, or other sensitive external identities unless a maintainer explicitly approves it. Use generic descriptors instead.
