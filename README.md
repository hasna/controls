# @hasna/controls

Spend-authorization / approval **control plane** over wallets + payments. Controls
is the plane that decides *whether money may move* and issues single-use, signed
authorization tokens the movers must present — it does not move money itself.

A single package ships the CLI + MCP + serve triad over a Hasna-contract store
(`bun:sqlite` local, cloud Postgres via the vendored storage-kit).

## Domain

| Concept | What it does |
|---|---|
| **policies** | Per-entity / per-agent spend caps (`transaction`/`day`/`week`/`month` window, amount, currency). |
| **counterparty_allowlists** | Who an entity may pay. Absent or blocked ⇒ denied. |
| **approval_rules** | Tiered thresholds → how many distinct approvals a spend needs. |
| **authorizations** | Single-use signed money-authorization tokens: `pending → approved → consumed` (or `rejected`/`expired`). |
| **freezes** | Emergency freeze per entity or per identity — blocks new requests and consumption. |
| **audit** | Append-only, hash-chained, tamper-evident money audit of every action. |

**Enforcement guarantees**

- **Spend caps** — a request that would breach any active cap (accumulated across the window) is refused.
- **Allowlist** — only allowlisted counterparties are payable.
- **Tiered approval** — amounts at/over a rule threshold require the configured number of distinct approvals.
- **Segregation of duties** — a requestor can never approve their own authorization.
- **Emergency freeze** — a freeze blocks new requests and consumption immediately.
- **Single-use tokens** — an approved token is HMAC-signed over `(id, entity, amount, currency, counterparty, requestor)` and may be consumed exactly once.

v0 **issues and records** authorization tokens and enforces its own caps / freeze /
SoD, and exposes the enforcement contract (`authorization.verify`) that
`iapp-wallets` / `iapp-payments` adopt. Making those upstream movers *refuse*
movements without a valid controls token is upstream/gated work.

## Money-Moving App Contract

Money-moving apps must call `evaluateMoneyMovementControls` or
`assertMoneyMovementControls` before any provider mutation. The contract is
read-only and fail-closed: it verifies the controls token, proves the token is
bound to the exact amount/currency/counterparty/requestor tuple, requires a
stable idempotency key, records counterparty verification and immutable policy
snapshot references, confirms the emergency-freeze check, and requires a
reconciliation reference.

Live execution is additionally blocked unless the movement includes both an
operator approval reference and sandbox evidence reference. After a provider
success, the moving app must consume the authorization exactly once with
`authorization.consume`; rejected, expired, consumed, frozen, mismatched, or
replayed tokens are denial cases.

First integration targets: `iapp-payments`, `iapp-treasury`, `iapp-wallets`,
`iapp-billing`, and `iapp-accounting`.

## Surfaces (interface parity)

CLI, MCP, and the `/v1` API expose the **same operations** over the same service
layer (generated from a single operation registry).

```bash
# CLI
controls policies create --entity-id <uuid> --window day --amount-limit 100000 --currency USD
controls allowlist allow --entity-id <uuid> --counterparty-id acme
controls authorizations request --entity-id <uuid> --requestor-id agent-a --amount 60000 --currency USD --counterparty-id acme
controls authorizations approve --entity-id <uuid> --id <auth> --approver-id agent-b
controls authorizations consume --entity-id <uuid> --id <auth> --token <token>
controls audit verify --entity-id <uuid>

# serve (Hono) — pinned port 3482
controls-serve   # GET /health /ready /version + /v1/entities/:entity_id/...

# MCP (Streamable HTTP + per-caller bearer auth) — pinned port 8886
controls-mcp --http --port 8886
```

## Storage & modes

- `local` (default): SQLite at `~/.hasna/controls/controls.db` is authoritative.
- `cloud` (`HASNA_CONTROLS_STORAGE_MODE=cloud`): PURE REMOTE — reads/writes go to
  the app's cloud Postgres via the vendored storage-kit (`sslmode=verify-full`).

## Security

- Copy-verbatim scope/role/entity-scoping auth stack, deny-by-default, timing-safe
  bearer compare, expiry + revocation. Auth is decoupled from storage mode and
  fails closed on any non-loopback bind.
- MCP `/mcp` requires a bearer token (§5.1a); `controls`/`access`/`treasury`/`billing`
  bind tokens to distinct credentials so SoD and approval tiers are attributable.
- `storage_status` is redacted (never emits a DSN); `storage_push/pull/sync` require
  `storage:admin`, are audited, and never touch the append-only audit table.

## Develop

```bash
bun install
bun run verify   # typecheck + test + build + conformance
```

License: Apache-2.0.
