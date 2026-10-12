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
| `POOL_MIN_SIZE` / `POOL_MAX_SIZE` | `1` / `5` | Connections per database pool |
| `POOL_MAX_DATABASES` | `8` | Max databases with an open pool (LRU eviction) |
| `AUTH_ENABLED` | `true` | Require login to the web UI |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / **required** | UI login (not a PostgreSQL account) |
| `SECRET_KEY` | random per start | Signs session cookies — **set it** for Docker/multi-worker |
| `SESSION_TTL_MINUTES` | `480` | Session lifetime |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
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

## How PostgreSQL semantics map to the UI

* **Users and roles are the same thing.** A *user* is a role with `LOGIN`; a *role* here is a role without it (a group). Toggling "Can log in" converts one to the other.
* **There is no DENY in PostgreSQL.** "Revoke" removes a *direct* grant. If access is still shown as *inherited* (dashed check), it comes from `PUBLIC` or from another role — the tooltip names the source, so you know what else to change.
* **Inheritance.** Privileges flow from roles a user is a member of when that membership has `INHERIT`. Since PostgreSQL 16 this is a per-membership option; the `Inherit privileges` switch sets the default for memberships created *afterwards*.
* **Superusers bypass everything.** The permissions page warns when a role is a superuser.
* **Deleting a role** that owns objects requires choosing another role to take ownership. The app runs `REASSIGN OWNED` (never drops objects), then `DROP OWNED` (removes remaining grants) in every database where the role has dependencies, then `DROP ROLE`. Per-database cleanup is not one atomic transaction across databases.
* **Default privileges** only affect objects created *after* they are set, and only those created by the chosen role (`FOR ROLE`; blank = the app's connection user).

Not covered: column-level privileges, row-level-security policies, large-object and type privileges, foreign data wrappers/servers, and managing `pg_hba.conf`.

## Design notes

**Safety**
* Every identifier is composed with `psycopg.sql.Identifier`; values with `Literal`. Privilege names are checked against a per-object-type allowlist (aware of the server version, e.g. `MAINTAIN` on 17+). Functions are addressed by `oid` and their signature is read from the catalog, never from the client.
* Permission edits are staged in the UI, shown as the exact SQL (**Review & apply**), then executed in **one transaction** — all or nothing.
* Passwords are sent to PostgreSQL as a pre-computed **SCRAM-SHA-256 verifier**, so plaintext never appears in server logs or `pg_stat_activity` (non-ASCII passwords fall back to server-side hashing).
* UI login uses a signed JWT in an `HttpOnly; SameSite=Strict` cookie; failed logins are throttled. Mutations are written to the `pgac.audit` log (who did what; passwords are never logged).
* The container runs as a non-root user with a read-only filesystem and all capabilities dropped.

**Performance**
* Permission reads are set-based: ACLs are expanded with `aclexplode` and inherited roles resolved with `pg_has_role` *inside one paginated query* — one round trip per page, no per-object queries. With 20,000 tables a 100-row page takes ~25–100 ms.
* Large result sets are paginated and filtered server-side (schema, name search, "only with access").
* Async psycopg pools, one per database, created lazily, health-checked, and evicted when idle. Role lists compute membership aggregates only for the rows on the page.
* GZip responses; hashed static assets are served with immutable caching; the UI bundle is ~85 kB gzipped.

## API

Interactive docs at `/api/docs`. Main resources: `GET/POST /api/roles`, `GET/PATCH/DELETE /api/roles/{name}`, `PUT /api/roles/{name}/member-of`, `PUT /api/roles/{name}/members`, `GET /api/roles/{name}/dependencies`, `GET /api/permissions/{role}/objects`, `GET /api/permissions/{role}/default-privileges`, `POST /api/permissions/{role}/apply` (`dry_run` supported), `GET /api/databases`, `GET /api/schemas`, `GET /api/meta`, `GET /api/health`.

## Project layout

```
backend/   FastAPI app (app/), services/ hold all SQL; tests/ integration tests
frontend/  Vite + React + TypeScript + TanStack Query
Dockerfile, docker-compose.yml, .env.example
```
