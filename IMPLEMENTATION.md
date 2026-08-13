# Autonoma Environment Factory integration

Autonoma seeds a whole tenant before each end-to-end run and removes it
afterwards, through the endpoint in `management/internals/modules/autonoma/`.
Every factory creates through the same manager the REST API and gRPC server use,
so a seeded row carries the real validation, hashing, activity events and
network-map updates rather than a raw insert's approximation of them.

SDK endpoint path: /api/autonoma

## Endpoint and plumbing

- [x] Autonoma Go SDK added (`github.com/autonoma-ai/sdk/sdks/go` v0.2.10)
- [x] Endpoint mounted at `/api/autonoma`, registered as an auth bypass path
- [x] `x-signature` HMAC verified by the SDK against `AUTONOMA_SHARED_SECRET`;
      an unsigned or wrongly signed request gets 401 `INVALID_SIGNATURE`
- [x] Scope field declared as `accountId`
- [x] Auth callback returns real credentials for the seeded owner
- [x] Teardown scoped to the seeded account
- [x] Maintenance note in `AGENTS.md`

## Factories

Every entity the entity audit lists as independently created, each validated
against the running server and the Postgres it writes to.

- [x] Account — `CreateUserWithPassword` + `GetOrCreateAccountByUser`
- [x] Settings — `UpdateAccountSettings`
- [x] installation — `SqlStore.SaveInstallationID`
- [x] User — `CreateUser`
- [x] PersonalAccessToken — `CreatePAT`
- [x] UserInviteRecord — `CreateUserInvite`
- [x] Group — `CreateGroup`
- [x] Peer — `AddPeer`
- [x] GroupPeer — `GroupAddPeer`
- [x] SetupKey — `CreateSetupKey`
- [x] Policy — `SavePolicy`
- [x] Checks — `SavePostureChecks`
- [x] Route — `CreateRoute`
- [x] NameServerGroup — `CreateNameServerGroup`
- [x] Network — `networks.CreateNetwork`
- [x] NetworkRouter — `routers.CreateRouter`
- [x] NetworkResource — `resources.CreateResource`
- [x] Job — inline insert, see below
- [x] Zone — `zones.CreateZone`
- [x] Record — `records.CreateRecord`
- [x] Proxy — `proxy.Connect`
- [x] Domain — `domain.CreateDomain`
- [x] Service — `service.CreateService`
- [x] ProxyAccessToken — inline insert, see below
- [x] AccessLogEntry — `accesslogs.SaveAccessLog`
- [x] Provider — `agentnetwork.CreateProvider`
- [x] AgentNetworkPolicy — `agentnetwork.CreatePolicy`
- [x] Guardrail — `agentnetwork.CreateGuardrail`
- [x] AccountBudgetRule — `agentnetwork.CreateBudgetRule`
- [x] Consumption — `agentnetwork.RecordAccountBudgetUsage`
- [x] AgentNetworkAccessLog — `agentnetwork.IngestAccessLog`

Models the audit lists as dependent get no factory: they are written by their
parent's create call and removed by its teardown. All of them were confirmed
present in the database after a seed.

- PolicyRule — written by `SavePolicy` with the policy
- ExtraSettings, AccountOnboarding — written by account provisioning
- NetworkAddress — written by `AddPeer` into the peer's system meta
- Target — written by `CreateService` with the service
- AgentNetworkAccessLogGroup, AgentNetworkUsage, AgentNetworkUsageGroup —
  derived by `IngestAccessLog` from the access log

## Validation

- [x] Every entity validated: up, rows confirmed in Postgres, down, rows gone
- [x] Full recipe up and down, 57 records across 31 entities, no leftovers
- [x] Wrong signature and missing signature both rejected with 401
- [x] Auth payload carries real credentials — they were used to walk the app's
      own OIDC login form end to end and exchange the code for an access token,
      which then answered on `/api/peers`, `/api/setup-keys` and the rest
- [x] Time-relative rows land on the intended side of now, checked through the
      application's own queries (see below)
- [x] `sdk check` on `recipe.json` prints `"ok": true`
- [x] Concurrent instances: `sdk up --repeat 3` brings three tenants up at once
      and tears all three down
- [x] `golangci-lint` clean on every package this touches
- [x] Branch pushed and pull request opened

### Fields the application compares against the current time

Each is seeded as an offset the factory adds to the clock at seeding time, and
each was read back through the app's own query rather than off the row:

| Field | Check |
| --- | --- |
| `SetupKey.ExpiresAt` | `GET /api/setup-keys` reports two `valid` keys and the third `expired` |
| `Peer.Status.LastSeen` | `GET /api/peers` shows four peers connected with a recent last-seen and the contractor's laptop offline two days back |
| `UserInviteRecord.ExpiresAt` | `GET /api/users/invites` reports the invite with `expired: false` |
| `PersonalAccessToken.ExpirationDate` | 30 days out, so the token authenticates for the whole run |
| `ProxyAccessToken.ExpiresAt` | `GET /api/reverse-proxies/proxy-tokens` reports it unrevoked and unexpired |
| `AccessLogEntry.Timestamp` | the five entries fall in the last ten minutes, inside the access-log view's default window |
| `AgentNetworkAccessLog.Timestamp` | `GET /api/agent-network/usage/overview` buckets both calls into today |
| `Consumption.WindowStartUTC` | `GET /api/agent-network/consumption` returns both counters in the current 30-day window |
| `Job.CreatedAt` | `GET /api/peers/{id}/jobs` returns the succeeded bundle job |

Durations that are not instants — the peer login expiration, the policy and
budget windows — stay concrete, because nothing compares them to now.

## Decisions worth knowing

**Two entities fall back to an inline write.** Both are cases the audit
describes: the application has no reusable creation function for them.

- **Job.** `AccountManager.CreatePeerJob` refuses to write unless the peer holds
  a live gRPC stream, and dispatches the request down it before persisting. A
  seeded peer has no agent process behind it, so the factory replicates the
  insert the manager runs inside its transaction and records the same
  `JobCreatedByUser` activity event, dropping only the dispatch and the
  connectivity gate. The peer's reported agent version is seeded at or above the
  0.64.0 minimum the manager enforces for remote jobs.
- **ProxyAccessToken.** The REST handler builds the record inline. The factory
  mints it through the canonical `types.CreateNewProxyAccessToken` generator and
  persists it, dropping the handler's request parsing and permission lookup.

**Four scoped deletes were added to `SqlStore`.** Peer jobs, reverse-proxy
access logs, agent-network telemetry and account-scoped proxy tokens have no
delete path in the application — retention sweeps age them out and tokens are
revoked rather than removed — and no foreign key or GORM association back to the
account, so `DeleteAccount` leaves them behind. Each new method is scoped by
account so it cannot reach another tenant's rows.

**The signing secret is derived when the environment supplies only the shared
one.** `AUTONOMA_SIGNING_SECRET` is read first and is the preferred
configuration; without it the endpoint derives a distinct secret from
`AUTONOMA_SHARED_SECRET`. A per-process random value would be stronger but would
invalidate every refs token across a restart, stranding a seeded tenant with no
way to tear it down.

**Where the recipe departs from `scenarios.md`.** Three places, each because the
scenario describes something the application does not do:

- *One rule per policy.* `validatePolicy` assigns every rule of a policy the
  policy's own id, so a second rule silently overwrites the first. The recipe
  therefore carries the scenario's three rules as three policies — the
  account's own `Default`, `Dev to DB` and `Block Contractors`.
- *Job types.* The scenario asks for `upgrade` jobs; the only workload the
  application defines is `bundle`, and its statuses are pending, succeeded and
  failed rather than completed.
- *Derived fields are not seeded.* Peer overlay addresses and DNS labels are
  allocated by `AddPeer`, and peer keys are globally unique, so the recipe
  supplies none of them. The `All` group and its five memberships are created by
  provisioning and by each `AddPeer`, so the recipe seeds only the other five
  groups and the five explicit memberships.

**Agent Network settings.** Ingesting an agent-network access log only writes
the full row when the account has gateway settings with log collection on, which
a real account gets when the gateway is switched on in the dashboard. The
`AgentNetworkAccessLog` factory bootstraps that row through
`agentnetwork.CreateSettings` if the account has none, using a per-account
endpoint so concurrent runs never contend on its globally unique domain index.
The account teardown removes it.

**Two repository conventions were knowingly set aside**, both because this work
was commissioned as the integration itself rather than proposed on its own:
`AGENTS.md` asks for an agreed ticket before a pull request, and for the user's
decision before adding a dependency. The dependency is the Autonoma Go SDK.
