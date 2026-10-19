# Class notes

Detail behind the `SKILL.md` checklist. Read only the sections your Phase 1
inventory points at.

Each section has the same shape:

- **Probe** — the smallest thing to send
- **Missing check** — what the guard looks like when it's absent, in code
- **Targets** — where this class actually pays off
- **Grey areas** — when it is *not* a bug

## Contents

- [Fast probes](#fast-probes)
- [BOLA / IDOR](#bola--idor)
- [BFLA](#bfla)
- [Mass assignment](#mass-assignment)
- [Tenant isolation](#tenant-isolation)
- [JWT and session](#jwt-and-session)
- [CORS](#cors)
- [WebSocket / SSE](#websocket--sse)
- [GraphQL](#graphql)
- [Route confusion](#route-confusion)
- [TOCTOU](#toctou)
- [Share links and invites](#share-links-and-invites)
- [SSRF](#ssrf)
- [Differential responses](#differential-responses)
- [Severity anchors](#severity-anchors)

## Fast probes

| Class | The single request |
|---|---|
| BOLA | A's object ID, B's token, `GET` then `PUT` |
| BFLA | lowest role → every route; then no token at all |
| Mass assignment | re-`POST` the create body with `role`/`is_admin`/`owner_id` added |
| Tenant | your token, their `org_id` in body — and their token, your `org_id` |
| JWT | `alg:none`; `HS256` signed with the public key; drop `aud`/`iss` |
| CORS | `Origin: https://evil.com` + `credentials: include` on a cookie endpoint |
| WebSocket | handshake as A, then frame referencing B's resource |
| GraphQL | one query, two aliases, two objects; then a nested field as low role |
| Route confusion | same route via `/v2/`, trailing slash, `PUT`, form-encoded |
| TOCTOU | two-step flow, lose the role between step 1 and step 2 |
| Share token | accept an invite issued for org A into org B |
| SSRF | webhook URL → `http://169.254.169.254/latest/meta-data/` |

## BOLA / IDOR

**Probe.** Swap the object ID for another account's, keep your token. Read path
then write path. Both directions. Every location: path, query, body, header,
cookie, claim.

**Missing check.** `find(id)` where it should be `findFirst({ id, userId })`.
Also: `getById()` called after a `list()` that *was* scoped; a guard checking
`projectId` but not the `taskId` inside it; an ownership check on `GET` that the
`PUT` handler never repeats.

**Targets.** Nested writes (`POST /teams/{mine}/members/{theirs}`), bulk and
batch endpoints taking a mixed ID list, export and report jobs, queue workers
that re-fetch by ID, soft-delete restore, `clone`/`duplicate`/`move`/`transfer`,
`parent_id`, `/me/...` aliases, `?user_id=`, item-in-collection
(`/orders/{id}/items/{item_id}`), GraphQL `node(id:)`.

**Second-order / confused deputy.** Where a stored ID from one object authorizes
access to another — an invite holding `inviter_id`, a webhook holding `owner_id`,
a token record holding `user_id`. The handler trusts the stored value instead of
re-deriving it.

**Grey areas.** Public-by-design objects (avatars, published posts, public
profiles) unless private fields leak. Team/org-shared visibility. An ID that
*is* the capability — signed, scoped, unguessable: say so explicitly rather than
reporting. Endpoints documented as "any authenticated user".

**ID transforms.** `1042` → `1041`, `1043`, `1`, `0`, `-1`, `999999999`,
`01042`, `1042.0`, `1e3`, `0x412`. UUID → base64-decode composite IDs
(`dXNlcjoxOjEyMw==` → `user:1:123`), decode UUIDv1 to a timestamp, try the
numeric `id` if the API takes a uuid, try the `slug`, try the GraphQL node ID.

## BFLA

**Probe.** Every route with the lowest role, then with no token at all.

**Missing check.** Route registered outside the guarded router; middleware
attached to a prefix while the route is mounted above it; guard present in the UI
only; guard on `POST` but not `PUT`/`PATCH`/`DELETE`; `HEAD`/`OPTIONS` reaching
the handler unguarded.

**Targets.** Role/status/plan mutation, `/admin/*`, `/internal/*`, `/debug`,
`/actuator/*`, `/console`, bulk import, webhook replay, feature-flag writes,
impersonation (`?as_user=`, `X-On-Behalf-Of`), CSV exports, GraphQL mutations
absent from the role map, tRPC procedures missing from the middleware chain.

**Inverse.** Privilege spoofing *upward* via a body field or claim — overlaps
mass assignment; check both.

**Grey areas.** Internal routes intentionally public. `OPTIONS` returning 200 is
normal. A route returning `401` rather than `403` is still a finding if it is
reachable *and* does the work.

## Mass assignment

**Probe.** Re-send a create/update body with extra fields, then read the object
back. Over-post, then confirm persistence.

**Fields.** `role`, `roles[]`, `is_admin`, `is_staff`, `verified`,
`email_verified`, `plan`, `tier`, `credits`, `balance`, `price`, `discount`,
`owner_id`, `user_id`, `tenant_id`, `org_id`, `created_at`, `deleted_at`,
`status`, `approved`, `permissions[]`, `scopes[]`, `id`.

**Missing check.** `Object.assign(entity, req.body)`, `{ ...req.body }` spread
into a model, a non-strict DTO, nested/associative writes, `PATCH` with a partial
schema, `updateMany` with an unwhitelisted object.

**Read side.** Serializer returning `password_hash`, `internal_notes`,
`stripe_customer_id`, `is_admin`, other users' emails, soft-deleted rows, draft
objects, internal IDs, full tenant rosters.

**Grey areas.** Frameworks that strip unknown keys by default. `id` in the body
being ignored is normal. A writable `created_at` is only a finding if it is
load-bearing.

## Tenant isolation

**Probe.** Two orgs. Cross every endpoint. Their `org_id` in your body while your
token says yours, and the reverse. Then swap only the *nested* tenant field.

**Missing check.** `org_id` read from `req.body`/`req.query` instead of the
session; query scoped by `user_id` but not `org_id`; tenant derived from the
subdomain or `Host` header and never validated; cache key omitting the tenant; a
shared parent (project, workspace) whose children inherit no scope; an invite
accepted into the wrong org; a share token granting more than intended; removing
a member not revoking their existing token.

**Grey areas.** Users legitimately in several orgs. Global resources (templates,
plans). Cross-org read of a *public* object that lives inside a private org.

## JWT and session

- `alg:none` accepted; **RS256 → HS256 confusion** (public key used as HMAC secret)
- weak or default HMAC secret; the same secret across environments;
  brute-forceable (`jwt-cracker`, `hashcat -m 16500`)
- `kid` path traversal, `kid` SQLi, `kid` pointing at an attacker-controlled file
- `jku` / `x5u` unvalidated → host your own JWKS
- **`aud` and `iss` unvalidated** — a token minted for service A accepted by B
- `exp` absent or ignored; `nbf`/`iat` ignored; clock skew abused
- **claims verified but never used for authz** — `role` set at signup and never
  re-checked; user demoted, token still admin
- `sub` type coercion: `"0"` vs `0`, `null`, `[]`, numeric-vs-string map lookup,
  two users colliding on a coerced key
- `sub` reused across tenants; user deleted but token still valid
- logout doesn't invalidate; refresh token reusable; refresh doesn't rotate;
  refresh accepts an access token; access token accepted as refresh
- reset / email-change tokens: reusable, no expiry, not bound to the user, not
  invalidated on use
- session fixation; `SameSite` missing on a cookie-authed API; token in a query
  string (referrer and log leak)

## CORS

Only matters when the credential is a **cookie** or HTTP auth. With a token in a
header, CORS is not authz.

- reflects `Origin` while also sending `Allow-Credentials: true`
- regex on origin: `evil-example.com` matching `*.example.com`;
  `example.com.evil.com`; a suffix without a dot boundary; an unescaped `.`
- `null` origin allowed with credentials (sandboxed iframe, `file://`)
- preflight allows a method the actual handler guards differently
- `Allow-Credentials: true` alongside a literal `*` origin
- missing `Vary: Origin` behind a shared cache
- also: `postMessage` with `targetOrigin: "*"` or no `origin` check on receive;
  OAuth `redirect_uri` matched by prefix instead of exactly

## WebSocket / SSE

**Probe.** Authenticate as A, then send frames referencing B's resources.
Subscribe to B's channel.

**Missing check.** Authz at `upgrade` only, never per-message. Server trusts an
`actor_id` in the frame. Channel names predictable and unscoped. `Origin`
unchecked on upgrade (CSWSH). Token in the query string. Socket outliving
logout. Broadcast sends full objects rather than projections. GraphQL
subscriptions with no per-event authz.

## GraphQL

- node/global ID swap; **two aliases in one query** hitting two objects
- field-level resolvers skipping the authz the top-level query enforces
- `@auth` on the type but not the mutation
- mutation reachable by a low role; `__typename`-driven type confusion on interfaces
- introspection on; `__schema` exposing internal types
- alias-based rate-limit bypass; batching via `[ ]`; deeply nested DoS
- persisted-query bypass (`GET ?query=`); `operationName` confusion
- nullable fields masking a `403` as `null`
- error messages leaking existence

## Route confusion

- trailing slash, case-insensitive routing, `%2e`, `..;/`, `//`, `/./`
- `/v1/` missing a check that `/v2/` has (and the reverse)
- middleware bound to a prefix while the route is mounted above it
- `X-HTTP-Method-Override`, `?_method=`, `HEAD` on a `GET` guard
- content-type switched to a different parser; duplicate JSON keys; XML
- proxy and app disagreeing on path (`X-Forwarded-Prefix`, `X-Rewrite-URL`)
- serverless globs (`/api/*`) not matching what you assume

## TOCTOU

- two-step flow where step 2 doesn't re-check ownership of step 1's object
- approve/reject/transfer by an actor who lost the role between steps
- double-spend of an invite, coupon, credit, or seat under concurrency
- role downgrade not revoking sessions or in-flight tokens
- `PATCH` racing a `PUT`; status transitions with no state validation
  (`refunded` → `shipped`)
- undo/rollback endpoints restoring a prior privileged state

## Share links and invites

- share token in a URL: replayed, unexpiring, unscoped, or granting more than the
  sharer had
- invite issued for org A accepted into org B
- `?token=` leaking via the referrer header; token in logs
- signed URL valid for the whole bucket, or for other keys
- predictable object-storage paths once authz is skipped
- remove-member not revoking the member's token or existing session

## SSRF

- server-side fetch of a user-supplied URL
- webhook URL → `http://169.254.169.254/latest/meta-data/`
- allowlist matched on the hostname string rather than the resolved IP; redirect
  following; DNS rebinding
- import-by-URL, image/PDF fetch, RSS, sitemap, oEmbed, avatar-from-URL

## Differential responses

Note it always; report it only when it enumerates something private.

- `404` for unauthorized = correct, hides existence
- `403` = confirms existence, leaks the ID space
- `200` with `null`/empty body = lookup miss, **not** access
- timing differences between scoped and unscoped lookups
- list endpoints whose count includes others' rows

Report as **P4** only if existence is itself sensitive — private objects,
invite-only tenants, a name attached to an ID.

## Severity anchors

| Class | Typical | Escalates when |
|---|---|---|
| Cross-tenant read/write | P1–P2 | pre-auth, or full row write |
| BOLA on a sensitive object | P2 | write path, PII/payment data |
| BOLA on a low-sensitivity object | P3 | bulk, or enumerable |
| BFLA to an admin action | P1–P2 | state-changing, or user management |
| Mass assignment of `role`/`owner_id` | P2 | persists and grants access |
| Read-side over-exposure | P3–P4 | secrets, `password_hash` |
| JWT forgery | P1 | no secret needed |
| CORS + credentials | P2–P3 | sensitive authed actions |
| Existence leak | P4 | private object space |