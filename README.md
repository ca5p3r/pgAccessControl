# pgAccessControl

A web console for managing **PostgreSQL roles, users and permissions** — React UI, Python (FastAPI) backend, runs in Docker.

| You want to…                                          | Where                                                    |
| ----------------------------------------------------- | -------------------------------------------------------- |
| Create / update / delete **users** and **roles**      | *Users* and *Roles* pages                                |
| Assign roles to users (and members to roles)          | A role's **Membership** tab                              |
| Grant / revoke on **databases, schemas, tables & views, sequences, functions** | A role's **Permissions** tab, or the *Permissions* page |
| See what a user or role can **currently** do          | Permissions grid — direct grants and inherited ones, with the source role |
| Set **default privileges** for future objects         | Permissions → *Default privileges*                       |
| Manage what **everyone** (PUBLIC) can do              | *Permissions* → PUBLIC                                   |
| Give access that **ends by itself** (grants and memberships) | *Make this temporary* when applying, or *set expiry* on a membership; manage under **Temporary access** |
| **Snapshot** permissions and catch **drift** (changes made outside the app) | *Reports* → Snapshots & drift |
| Let **several people** in with limited rights, or use **SSO** | *Accounts* (admin) and the `OIDC_*` settings |
| Manage **several PostgreSQL servers** and switch between them | The **server switcher** (top of the sidebar, `Alt+S`) and the *Servers* page (admin) |
| Set **column-level** privileges, **grant option** and **grantor** | *columns* link on a table row; *Grant option* mode; Review → Advanced |
| See everything a user or role **holds** (owned objects, grants, default privileges, grants it gave to others), e.g. before deleting it | A role's **Held grants** tab; the delete dialog links to it |
| See **who changed what**, with the SQL and before/after values | *Activity* page, and a role's **Activity** tab  |
| Find out **who can access** a table, view, sequence, function, schema or database | *Reports* → Who has access? (also a link on every grid row) |
| **Export** permissions as SQL, CSV or JSON (whole database or one user/role) | *Reports* → Export, or the Export button on a role's Permissions tab |

## Quick start (Docker)

```bash
cp .env.example .env          # then edit PG_*, ADMIN_PASSWORD, SECRET_KEY
docker compose up -d --build
# open http://localhost:8000
```

Want to try it without a database? Add the bundled throw-away PostgreSQL:

```bash
docker compose --profile demo up -d --build     # PG_HOST=db in .env (the default)
```

To administer an existing server, set `PG_HOST` (use `host.docker.internal` for a server on the Docker host).

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `PG_HOST` / `PG_PORT` | `localhost` / `5432` | PostgreSQL server |
| `PG_USER` / `PG_PASSWORD` | `postgres` / – | Account used to administer (superuser recommended) |
| `PG_DATABASE` | `postgres` | Maintenance DB for cluster-wide queries |
| `PG_SSLMODE` | `prefer` | libpq SSL mode (`require`, `verify-full`, …) |
| `PG_SERVER_NAME` / `PG_ENVIRONMENT` / `PG_READ_ONLY` | `Default server` / `other` / `false` | How the `PG_*` server appears in the switcher, its environment tag, and whether it is view-only |
| `ENCRYPTION_KEY` | – | Encrypts passwords of servers added in the UI. **Set it** to save passwords |
| `ENCRYPTION_KEY_PREVIOUS` | – | Old key during rotation (decrypt only; passwords are re-encrypted at startup) |
| `SERVER_MANAGEMENT_ENABLED` | `true` | `false` hides adding/changing servers in the UI |
| `SERVER_HOST_ALLOWLIST` | – | Host names, `*.suffix` or CIDRs that servers may point to (empty = any) |
| `MAX_SERVER_PROFILES` / `MAX_OPEN_SERVERS` | `50` / `16` | Limits on configured servers and on servers with open connections |
| `POOL_MIN_SIZE` / `POOL_MAX_SIZE` | `1` / `5` | Connections per database pool |
| `POOL_MAX_DATABASES` | `8` | Max databases with an open pool (LRU eviction) |
| `AUTH_ENABLED` | `true` | Require login to the web UI |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / **required** | UI login (not a PostgreSQL account) |
| `SECRET_KEY` | random per start | Signs session cookies — **set it** for Docker/multi-worker |
| `SESSION_TTL_MINUTES` | `480` | Session lifetime |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `LOCAL_LOGIN_ENABLED` | `true` | Password sign-in (built-in admin and accounts). `false` = SSO only |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | – | Enable single sign-on (OpenID Connect) |
| `OIDC_ADMIN_GROUPS` / `OIDC_OPERATOR_GROUPS` / `OIDC_VIEWER_GROUPS` | – | Group names (comma separated) that map to each role |
| `OIDC_DEFAULT_ROLE`, `OIDC_GROUPS_CLAIM`, `OIDC_USERNAME_CLAIM`, `OIDC_REDIRECT_URI`, `OIDC_SCOPES`, `OIDC_BUTTON_LABEL` | see `.env.example` | SSO details |
| `DATA_DB_PATH` | `data/app.db` (`/data/app.db` in Docker) | Accounts, temporary-access schedules, snapshots |
| `SCHEDULER_INTERVAL_SECONDS` | `30` | How often temporary access is checked |
| `DRIFT_CHECK_INTERVAL_MINUTES` | `0` (off) | Scheduled comparison of baseline snapshots with the live server |
| `AUDIT_ENABLED` | `true` | Store audit history (SQLite) |
| `AUDIT_DB_PATH` | `data/audit.db` (`/data/audit.db` in Docker) | Where history is stored; Docker mounts the `appdata` volume at `/data` |
| `AUDIT_RETENTION_DAYS` | `365` | Older entries are deleted daily; `0` keeps everything |
| `WORKERS`, `LOG_LEVEL`, `HOST`, `PORT` | `1`, `info`, `0.0.0.0`, `8000` | Server |
| `CORS_ORIGINS` | – | Only if the UI is served from another origin |

The connecting PostgreSQL account must be able to do what you ask of the UI: a **superuser** can do everything; a non-superuser needs `CREATEROLE` and rights over the roles and objects it manages.

## Local development

```bash
# Backend (Python 3.11+)
cd backend
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt    # Windows: .venv\Scripts\pip
cp ../.env.example .env && edit it (PG_HOST=localhost …, AUTH_ENABLED=false is handy)
.venv/bin/python -m app                       # API on :8000, docs at /api/docs

# Frontend (Node 20+), in another terminal
cd frontend
npm install
npm run dev                                   # http://localhost:5173, proxies /api to :8000
```

### Tests

The backend tests are integration tests against a **real PostgreSQL server** (they create and drop a `pgac_test` database and roles named `t_*` — never point them at production):

```bash
cd backend
TEST_PG_HOST=127.0.0.1 TEST_PG_PORT=5432 TEST_PG_USER=postgres TEST_PG_PASSWORD=... pytest
```

Frontend: `npm run build` runs the TypeScript type-check.

## Managing several servers

The server configured with `PG_*` variables is always there as the **default server**. Admins add more under **Servers**, and everyone switches between the ones they may use with the **server switcher** at the top of the sidebar (also `Alt+S`): it shows each server's environment, read-only state and live health, supports search and keyboard navigation, and remembers your choice.

* **Everything is per server**: users and roles, permissions, activity history, temporary access (which is revoked on the server it was granted on), snapshots and drift checks. Switching starts a clean slate in the browser, so nothing from one server can show up on another.
* **Safe by default for production**: tag a server *production* and it gets a red banner on every page and an extra confirmation before changes are applied or a role is deleted. Tag it *staging* / *development* for coloured labels.
* **Read-only servers** (a switch on the server): nobody can change anything on it through the console, whatever their role. This is enforced on the server, not just hidden in the UI, and does not affect administering accounts or the server list.
* **Visibility**: each server has a minimum role that may see it (everyone / operators / admins only). A server you may not use looks exactly like one that does not exist, and its activity history is hidden from you too. Only admins see host names and connection details.
* **Passwords** are encrypted with AES-256-GCM using `ENCRYPTION_KEY` and bound to their profile, are write-only (never returned by the API, never in logs or the audit trail, not even to admins), and a saved password is only ever sent to the address it was saved for: changing the host, port or user requires entering it again, so it cannot be redirected to another machine.
* **Connection safety**: TLS options up to `verify-full` with your own CA certificate, link-local and cloud-metadata addresses are blocked, an optional host allowlist (`SERVER_HOST_ALLOWLIST`), rate-limited connection tests, and a cap on how many servers keep connections open. Servers added in the UI use `verify-full` by default and the form warns when a connection can fall back to plain text.
* **Test before you save**: *Test connection* reports latency, PostgreSQL version, the account's rights and whether the connection is encrypted, with plain-language hints for common failures.
* Removing a server only removes it from the console: nothing is changed on PostgreSQL. Its scheduled expiries are cancelled and its snapshots deleted; its activity history stays (admins can still read it under *All servers*).
* Existing installations upgrade automatically: everything created before this feature belongs to the default server.

Limits: client-certificate authentication is not supported; hosts are checked when saved (DNS can change later); with several workers, a change made on one can take a few seconds to show on another.

## Accounts, roles and single sign-on

Anyone who signs in is a **viewer**, **operator** or **admin**:

| | viewer | operator | admin |
|---|:-:|:-:|:-:|
| Look at users, roles, permissions, reports, activity, snapshots | ✔ | ✔ | ✔ |
| Grant / revoke, change memberships, create and edit everyday roles, temporary access, snapshots | | ✔ | ✔ |
| Set `SUPERUSER`, `CREATEROLE`, `REPLICATION`, `BYPASSRLS`; modify or hand out privileged roles (superusers, `CREATEROLE`, `pg_execute_server_program`, `pg_read_all_data`, …) | | | ✔ |
| Delete roles; manage console accounts | | | ✔ |

Operators cannot escalate: they cannot reset the password of a privileged role, add anyone to one, or create one. Roles are checked on every request, so disabling an account or changing its role takes effect immediately.

* The **built-in admin** (`ADMIN_USERNAME` / `ADMIN_PASSWORD`) always works as a break-glass account. Create further accounts under **Accounts** (admin only; passwords are stored as scrypt hashes, 10+ characters).
* **SSO**: set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and register `https://<host>/api/auth/oidc/callback` as the redirect URI at your provider (Keycloak, Entra ID, Okta, Google, Authentik …). The authorization-code flow with PKCE is used; the ID token's signature, issuer, audience, expiry and nonce are verified. Map provider groups to roles with `OIDC_ADMIN_GROUPS`, `OIDC_OPERATOR_GROUPS`, `OIDC_VIEWER_GROUPS` (highest match wins; users matching none are refused unless `OIDC_DEFAULT_ROLE` is set). Set `LOCAL_LOGIN_ENABLED=false` for SSO only.
* Everything, including sign-ins and who made each change, appears in **Activity** under the real person's name.

## Temporary access

PostgreSQL can only expire passwords, so the app keeps a schedule and a background job revokes access on time.

* **Grants:** in *Review & apply* tick **Make this temporary** and pick a time (presets: 1 hour … 30 days). Works for grants on individual objects (database, schema, table, sequence, function, column), not for bulk or default privileges.
* **Memberships:** on a role's *Membership* tab click **set expiry** next to a membership.
* **Safe by design:** only privileges that were *not already held* are scheduled for revocation, so an expiring grant never removes a permanent one (these are listed as "already granted permanently"). A grant option that is added temporarily is the only thing removed at expiry if the privilege itself was already held.
* **Manage** under *Temporary access*: change the time, **keep** the access permanently, or **end now** (also retries a failed revocation). Expirations are recorded in *Activity* as `access.expired`, performed by `scheduler`.
* If the app is down at the deadline, access is removed as soon as it starts. The job checks every `SCHEDULER_INTERVAL_SECONDS`; several app instances share the schedule safely.

## Snapshots and drift

*Reports → Snapshots & drift*: **Take snapshot** saves roles, memberships, privileges (including columns) and default privileges of a database; passwords are never part of it. Open a snapshot to **compare it with the live server** (or with another snapshot) and see everything added, removed or changed since, including changes made directly with `psql` that the audit history cannot see. **Remediation SQL** shows what would restore the snapshot; it is only a script, never executed by the app, and it suggests (but never emits) `DROP ROLE` for roles created since.

Mark a snapshot as the **baseline** (the approved state) and set `DRIFT_CHECK_INTERVAL_MINUTES` to compare it automatically. New drift is written once to *Activity* (`drift.detected`) and to the server log for your alerting, and `drift.cleared` when it matches again.

## Fine-grained permissions

* **Column-level privileges** (`SELECT`, `INSERT`, `UPDATE`, `REFERENCES`): the *columns* link on a table row opens a column grid; table-level grants that already cover every column are shown as dotted checks.
* **Grant option:** switch the grid to *Grant option* mode and click granted cells to add or remove `WITH GRANT OPTION`. Revoking an option someone has passed on needs **cascade** (Review → Advanced).
* **Grantor:** Review → Advanced → *Grant as* runs the statements under `SET LOCAL ROLE`, so a role that holds the privilege WITH GRANT OPTION is recorded as the grantor (PostgreSQL's own `GRANTED BY` only accepts the current user).
* **Membership options** (PostgreSQL 16+): per membership **Admin**, **Inherit** and **SET ROLE** toggles on the Membership tab.

## Activity (audit history)

Every create, update, delete, membership change, permission change, temporary-access event, snapshot, account change, export and sign-in made **through this app** is stored with: who (and from which IP), when, a readable summary, the exact SQL that ran (passwords redacted), before/after values, and the error if it failed. Failed attempts are kept too, including the SQL that was tried. Previews ("Review & apply") change nothing and are not recorded.

* **Activity page**: search and filter by type, person, outcome and date range; click a row for details; switch on *Live* to follow changes; download the filtered list as CSV or JSON.
* **Per role**: the *Activity* tab shows the history of one user or role. The dashboard shows the latest entries.
* **Monitoring from outside**: each entry is also written to the `pgac.audit` logger as one JSON line, so Loki / ELK / Datadog / CloudWatch can collect it and alert on patterns (e.g. a new superuser).
* **Limits**: changes made directly with `psql` or other tools are not visible here. To capture those, enable PostgreSQL's own `pgaudit` extension or `log_statement = 'ddl'`.

## Reports and exports

* **Who has access?** Pick an object and see every user and role that can use it and *why*: a direct grant, PUBLIC, inherited from a named role, ownership, or superuser. Access is computed by PostgreSQL itself (`has_*_privilege`), so it always matches what the server would allow. Export the result as CSV.
* **Export**: a **SQL script** (`CREATE ROLE`, memberships, `GRANT`, `ALTER DEFAULT PRIVILEGES`) that can be replayed on another server, a **CSV** of one dataset (privileges, roles, memberships, defaults) for access reviews, or a **JSON** document. Limit it to one user/role or PUBLIC. Passwords are never exported, only explicit grants are listed (not implicit owner privileges), and revokes of default PUBLIC privileges are not reproduced. CSV cells starting with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets don't execute role names as formulas.

## How PostgreSQL semantics map to the UI

* **Users and roles are the same thing.** A *user* is a role with `LOGIN`; a *role* here is a role without it (a group). Toggling "Can log in" converts one to the other.
* **There is no DENY in PostgreSQL.** "Revoke" removes a *direct* grant. If access is still shown as *inherited* (dashed check), it comes from `PUBLIC` or from another role — the tooltip names the source, so you know what else to change.
* **Inheritance.** Privileges flow from roles a user is a member of when that membership has `INHERIT`. Since PostgreSQL 16 this is a per-membership option; the `Inherit privileges` switch sets the default for memberships created *afterwards*.
* **Superusers bypass everything.** The permissions page warns when a role is a superuser.
* **Deleting a role** that owns objects requires choosing another role to take ownership. The app runs `REASSIGN OWNED` (never drops objects), then `DROP OWNED` (removes remaining grants) in every database where the role has dependencies, then `DROP ROLE`. Per-database cleanup is not one atomic transaction across databases.
* **Default privileges** only affect objects created *after* they are set, and only those created by the chosen role (`FOR ROLE`; blank = the app's connection user).

Not covered: row-level-security policies, large-object and type privileges, foreign data wrappers/servers, and managing `pg_hba.conf`.

## Design notes

**Safety**
* Every identifier is composed with `psycopg.sql.Identifier`; values with `Literal`. Privilege names are checked against a per-object-type allowlist (aware of the server version, e.g. `MAINTAIN` on 17+). Functions are addressed by `oid` and their signature is read from the catalog, never from the client.
* Permission edits are staged in the UI, shown as the exact SQL (**Review & apply**), then executed in **one transaction** — all or nothing.
* Passwords are sent to PostgreSQL as a pre-computed **SCRAM-SHA-256 verifier**, so plaintext never appears in server logs or `pg_stat_activity` (non-ASCII passwords fall back to server-side hashing).
* UI login uses a signed JWT in an `HttpOnly; SameSite=Strict` cookie; failed logins are throttled. Every mutation is stored in the audit history (see *Activity*); passwords are never stored or logged.
* The container runs as a non-root user with a read-only filesystem and all capabilities dropped.

**Performance**
* Permission reads are set-based: ACLs are expanded with `aclexplode` and inherited roles resolved with `pg_has_role` *inside one paginated query* — one round trip per page, no per-object queries. With 20,000 tables a 100-row page takes ~25–100 ms.
* Large result sets are paginated and filtered server-side (schema, name search, "only with access").
* Async psycopg pools, one per database, created lazily, health-checked, and evicted when idle. Role lists compute membership aggregates only for the rows on the page.
* GZip responses; hashed static assets are served with immutable caching; the UI bundle is ~85 kB gzipped.

## API

Interactive docs at `/api/docs`. Main resources: `GET/POST /api/roles`, `GET/PATCH/DELETE /api/roles/{name}`, `PUT /api/roles/{name}/member-of`, `PUT /api/roles/{name}/members`, `GET /api/roles/{name}/dependencies`, `GET /api/permissions/{role}/objects`, `GET /api/permissions/{role}/default-privileges`, `POST /api/permissions/{role}/apply` (`dry_run` supported), `GET /api/audit` (+ `/facets`, `/export`), `GET /api/access-report`, `GET /api/objects`, `GET /api/export`, `GET /api/databases`, `GET /api/schemas`, `GET /api/meta`, `GET /api/health`.

## Project layout

```
backend/   FastAPI app (app/), services/ hold all SQL; tests/ integration tests
frontend/  Vite + React + TypeScript + TanStack Query
Dockerfile, docker-compose.yml, .env.example
```
