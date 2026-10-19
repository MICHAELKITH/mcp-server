---
name: bug-review
description: Audit source, API traffic, JS bundles, and app config for broken
  authorization and access control — IDOR/BOLA, BFLA, mass assignment, trusted
  JWT claims, CORS-with-credentials, per-object authz in GraphQL and WebSocket,
  cross-tenant leaks, route/method/version confusion. Use when the user pastes
  source, endpoints, captured requests and responses, a bundle, or config and
  asks "is this IDOR?", "audit this API", "what can an attacker do?", or wants a
  triage pass before filing a bounty. Outputs a ranked table plus one evidence
  block per finding with a minimal repro and retest steps.
---

# Bug Review

Find **authorization and access-control** defects. Assume the target is
authorized and in scope unless told otherwise.

## When to use

- User pastes source, a request/response pair, a JS bundle, or config
- User asks "is this IDOR?", "audit this API", "what can an attacker do here?"
- User wants a triage pass before submitting a bounty report

Not covered: XSS, injection, crypto, race conditions beyond authz TOCTOU. Say so
if the material is really one of those rather than force-fitting it.

## Phase 0 — Scope (3 lines, max)

State back before analyzing: target, auth model assumed, what you were handed vs
what you'd need. Don't ask questions you can answer by proceeding.

## The one question

Authorization bugs are **missing checks**, not broken logic. For every
attacker-controlled value that reaches a handler, ask: *which authz model is
absent — object, function, field, or tenant — and whose other value would still
pass?*

| Model | Question | Typical class |
|---|---|---|
| Object | Can actor A reach B's object by ID? | BOLA / IDOR |
| Function | Can the wrong role reach this endpoint at all? | BFLA |
| Field | Does the response over-expose? Can the client over-post? | Mass assignment |
| Tenant | Does a request cross an org boundary? | Cross-tenant leak |

If you cannot state the missing check in one sentence, it is a hunch, not a
finding. Label it **suspected** and say what would confirm it.

## Phase 1 — Identifier inventory

Table only. No commentary yet.

| Value | Location | Endpoint(s) | Method | Who sets it |
|---|---|---|---|---|
| `invoice_id` | path | `/api/v1/invoices/{id}` | GET, PUT, DELETE | client |
| `org_id` | body | `/api/v1/projects` | POST | client ← flag |
| `tenant` | JWT claim | all | — | server |

Locations to sweep: path, query, body, headers (`X-User-Id`, `X-Tenant-Id`,
`X-Org-Id`, `X-On-Behalf-Of`), cookies, JWT claims, form fields, GraphQL args.
Also list the roles available and what each *should* be allowed to do.

Cap: if the paste is huge, list only values that appear in more than one place
or that gate a write. Say what you skipped.

## Phase 2 — The swap test

Do this before walking any checklist.

1. Need **two accounts**, ideally in **two tenants**. If you only have one, say so.
2. For each row in Phase 1: read A's object as B, then write A's object as B.
   Both directions.
3. Swap the value in **every** location it can appear — path, query, body,
   header, cookie, claim. The same value is often checked in one place only.
4. Then swap the **other** identifiers while keeping the first one yours:
   `tenant_id`, `org_id`, `owner_id`, `parent_id`, `workspace_id`. Nested-object
   swaps are where confused-deputy bugs live.
5. Numeric probes on any integer ID: `0`, `-1`, `1`, own−1, own+1, very large.
6. UUID is **not** safe. Base64-decode composite IDs. Check UUIDv1 timestamps,
   slugs that bypass the ID path, node IDs that decode to type + PK.

A `200` is not access. Compare the **body**.

## Phase 3 — The transformation ladder

When you get `403`, `404`, or `405` and are tempted to stop, try in order. Most
BOLA is one rung down.

1. Sibling method: `HEAD`, `PUT`, `PATCH`, `DELETE`, `POST`.
2. Route normalization: trailing slash, case, `%2e`, `..;/`, double-encoding, `//`.
3. Version and prefix: `/v1/` → `/v2/`, `/beta/`, `/internal/`, `/api/` vs
   `/api/v2/`, `/graphql` vs `/api/graphql`.
4. Content-Type: JSON → form-encoded → multipart → XML.
5. Value relocation: query → body → header. Also send it in both and disagree.
6. Shape confusion: `id=1` → `id[]=1` → `id[0]=1` → duplicate keys.
7. Alternate identifier: uuid → numeric `id` → `slug` → `username` → node ID.
8. Second-order: pass the *owner's* id where your own is expected.
9. `X-HTTP-Method-Override`, `?_method=`, `X-Forwarded-*`.
10. Drop auth entirely. Checks are often only on the authenticated branch.

## Phase 4 — Classify

Every pair from Phase 1 against every surface. Fill the cells; skip none.

| Surface \ Model | Object | Function | Field | Tenant |
|---|---|---|---|---|
| REST/JSON | A reaches B's row | wrong role reaches route | over-post `role`/`is_admin`/`owner_id`; response over-exposes | cross-org via body `org_id` |
| GraphQL | node/global-ID swap, alias two objects in one query | mutation reachable by low role, introspection | field-level authz, `__typename` leak | resolver scopes by arg not context |
| tRPC / RPC (`?method=`, `/api/fn`) | id in payload | procedure missing from the guard list | input passthrough to ORM | — |
| WebSocket / SSE | authz at handshake only, not per-message | subscribe to others' channels | full object broadcast | room/tenant topic confusion |
| Signed URLs / files | token grants whole bucket | — | — | predictable path |
| Server actions / RSC | action id guessable, args client-supplied | — | — | — |
| Admin / internal | — | normal role reaches it | — | — |

Direction on every finding: **horizontal** (same role, other user) or
**vertical** (lower role, higher privilege).

Always check the write path. `PUT`/`PATCH`/`DELETE` on someone else's row pays
more than the `GET` and is checked less often.

## Phase 5 — Prove and report

One block per finding. Concrete values, not `<id>`.

```text
### [P2] BOLA — GET /api/v1/invoices/{id} (horizontal, read)
**Where**  InvoiceController#show, route line 42
**Missing check**  loads by PK with no ownership predicate
**Evidence**
  A  GET /api/v1/invoices/1042  Bearer <alice>  → 200 {"id":1042,"total":"€9,400"}
  B  GET /api/v1/invoices/1042  Bearer <bob>    → 200 {"id":1042,"total":"€9,400"}
**Impact**  any authed user reads any invoice
**Confidence**  confirmed
**Repro**  curl -s -H "Authorization: Bearer $BOB" https://t/api/v1/invoices/1042
**Retest**  bob → 403/404 after fix; alice still 200
**Fix**  scope to `req.user.tenant_id`
```

For a **suspected** finding, replace Evidence with the differential you'd need
and keep the block — don't drop it.

Emit the ranked table first, before any detail:

| # | Sev | Class | Endpoint | Dir | Conf |
|---|---|---|---|---|---|
| 1 | P2 | BOLA | GET /api/v1/invoices/{id} | H | confirmed |

## Class checklist

Read only the sections of `references/classes.md` that your Phase 1 inventory
points at.

- [BOLA/IDOR](references/classes.md#bola--idor) on every ID-bearing endpoint, read and write
- [BFLA](references/classes.md#bfla): admin/internal reachable by normal role
- [Mass assignment](references/classes.md#mass-assignment) on create/update
- [Tenant isolation](references/classes.md#tenant-isolation) — is `org_id` from the token or the body?
- [JWT and session](references/classes.md#jwt-and-session) — forgery, lifetime, revocation
- [CORS](references/classes.md#cors) — reflected `Origin` + credentials on cookie auth
- [WebSocket / SSE](references/classes.md#websocket--sse) — handshake-only authz
- [GraphQL](references/classes.md#graphql) — field-level authz, aliases, batching
- [Route confusion](references/classes.md#route-confusion) — version, method, path, content-type
- [TOCTOU](references/classes.md#toctou) — two-step flows, downgrade between steps
- [Share links and invites](references/classes.md#share-links-and-invites)
- [SSRF-adjacent](references/classes.md#ssrf) — server-side fetch of a user-supplied URL
- [Differential responses](references/classes.md#differential-responses) — 200 vs 403 vs 404
- Response over-exposure: extra fields, internal IDs, soft-deleted records

## Severity

Inputs: sensitivity, blast radius (one row vs every tenant), pre-auth or not,
read vs write.

- **P1** — unauthenticated or cross-tenant full read/write, admin takeover
- **P2** — authenticated cross-user read/write on sensitive data
- **P3** — cross-user on low-sensitivity data, field over-exposure
- **P4** — info leak aiding another attack, enumeration
- **P5** — hardening, defense-in-depth

Bump one level if state-changing. Bump one level if no session is required. Cap
at P1. Tag each finding `reportable` or `likely N/A` — bounty triage often
rejects P5, introspection-on, unauthenticated `/health`.

## Do not report these

- `200` with empty or `null` body — a lookup miss, not access
- sequential IDs alone — need the missing-check argument
- `403` vs `404` divergence — usually deliberate masking
- `ACAO: *` on its own — only with `Allow-Credentials: true`, and only on cookie auth
- GraphQL introspection enabled
- public-by-design objects, unless private fields leak
- `/health`, `/metrics`, `/version` unauthenticated

## Output discipline

- Ranked table first, then details. Nothing else before it.
- Details for P1–P3 only; one line each for P4/P5.
- Don't restate the input. Don't re-explain what IDOR means.
- Quote ≤3 lines of code per finding.
- If the material was insufficient, end with **"To go further I'd need:"** and a
  short list — don't pad.

## Rules

1. In scope only; flag anything you'd call out-of-scope.
2. One finding per block. Never merge unrelated bugs.
3. Suspected ≠ confirmed. Say which, every time.
4. State the missing check or downgrade to a hunch.
5. Analyze pasted material by default. Call tools only to confirm, or when the
   user asks — but do hand back a runnable `curl`, and a minimal HTML page for
   cookie/CORS-class bugs.
6. No severity inflation. No exploit narrative beyond the evidence.
7. Never claim a fix without having seen the guard that's missing.