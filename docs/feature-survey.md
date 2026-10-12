# Feature survey: comparable PostgreSQL role / permission tools

> **Implementation status:** the audit history, export and "who has access" report, per-membership options, grant-option toggle and grantor choice, column-level privileges, multiple console accounts with viewer/operator/admin roles and OIDC single sign-on, time-limited access, and snapshot/drift detection (with optional scheduled checks) are all implemented. Still open from this survey: approval workflows, managing several PostgreSQL servers from one console, and `pg_hba.conf` management.

> **Corrections after checking the pgAccessControl code** (the survey could only read the README):
> * Gap 1 is mostly **already built**: the user/role form has LOGIN, SUPERUSER, CREATEDB, CREATEROLE, INHERIT, REPLICATION, BYPASSRLS, connection limit, password expiry (VALID UNTIL), password generation and comments. Still missing: role-level config parameters (`ALTER ROLE ... SET`).
> * Gap 2 is **partly built**: `WITH GRANT OPTION` is supported by the API and the bulk-grant panel, and the grid marks grants that carry it. Still missing: per-cell toggle in the grid and choosing the grantor.
> * Gap 3 is **not built**: memberships show `admin_option` but ADMIN/INHERIT/SET per membership (PG16+) cannot be edited.

Survey date: 2026-10-12. Method: vendor docs and project pages read via web fetch/search. A cell is marked only when a source page stated it; "?" means the pages I could read did not say either way (not that the feature is absent). Statements about pgAccessControl come from its README only, so "?" in that column means "README silent, check the code".

## 1. Tools surveyed

| Tool | What it is | Source |
| --- | --- | --- |
| pgAdmin 4 | The standard PostgreSQL GUI; role dialog, per-object privilege editors, Grant Wizard, Reassign/Drop Owned dialog | https://www.pgadmin.org/docs/pgadmin4/latest/role_dialog.html , https://www.pgadmin.org/docs/pgadmin4/latest/grant_wizard.html , https://www.pgadmin.org/docs/pgadmin4/7.8/role_reassign_dialog.html |
| DataGrip | JetBrains IDE; "Modify Role" dialog with a Grants pane and editable SQL preview | https://www.jetbrains.com/help/datagrip/database-users-and-roles.html |
| pgControl (fatihemre) | Self-hosted PostgreSQL governance panel; the closest direct competitor (effective-privilege explainer, plan/apply, audit log, SSO) | https://hub.docker.com/r/fatihemre/pgcontrol |
| Bytebase | Database DevSecOps platform; its own RBAC, just-in-time access requests with approval and expiry, data masking, audit log | https://www.bytebase.com/database-access-control.md , https://docs.bytebase.com/security/database-permission/just-in-time.md , https://docs.bytebase.com/administration/roles , https://docs.bytebase.com/security/audit-log |
| Teleport (Database Access) | Access-proxy platform; auto-provisions DB users on connect, maps Teleport roles to DB roles/object permissions, access requests with reviewers | https://goteleport.com/docs/enroll-resources/database-access/auto-user-provisioning/postgres/ , https://goteleport.com/docs/identity-governance/access-requests/ |
| ldap2pg (Dalibo) | CLI that syncs roles, memberships and privileges from LDAP or YAML; dry-run by default | https://ldap2pg.readthedocs.io/en/latest/ , https://ldap2pg.readthedocs.io/en/latest/privileges/ |
| pgbedrock (Squarespace) | Declarative YAML spec for roles, memberships, ownership and read/write privileges; enforces the spec against the live DB | https://pgbedrock.readthedocs.io/en/latest/spec_overview.html , https://pgbedrock.readthedocs.io/en/latest/project_goals.html |
| CloudNativePG declarative roles | Kubernetes operator feature: roles declared in the cluster manifest and continuously reconciled | https://cloudnative-pg.io/docs/1.27/declarative_role_management |
| Terraform PostgreSQL provider (cyrilgdn) | IaC resources for roles, grants and default privileges (read only through search summaries, not the registry docs) | https://docsearch.algolia.com/mcp/docs/repo/cyrilgdn/terraform-provider-postgresql |
| Ansible community.postgresql | Modules for users, privileges and membership (search summaries only) | https://docs.ansible.com/ansible/latest/collections/community/postgresql/ |
| pg_permissions (Cybertec) | SQL extension giving permission-report views and an expected-vs-actual diff function | https://www.cybertec-postgresql.com/en/pg_permission-inspecting-your-postgresql-security-system/ |
| pgrights | Desktop GUI for roles, table/column privileges and RLS policies (small, last pushed 2022) | https://github.com/apsavin/pgrights |
| Neon console / Aiven console | Managed-service UIs: only create/delete role, generated password, reset password | https://neon.com/docs/manage/roles/ , https://aiven.io/docs/products/postgresql/howto/manage-service-users |
| Postgres Enterprise Manager (EDB) | Commercial monitoring suite with its own admin roles and an Audit Manager (configures server-side audit logging, not privilege management) | https://www.enterprisedb.com/docs/pem/8.1.0/pem_online_help/01_toc_pem_getting_started/04_pem_roles/ |

Could not verify (see section 4): DBeaver, Supabase dashboard, Adminer, pgweb, AWS RDS and Cloud SQL consoles.

## 2. Feature comparison matrix

Columns: pgAC = pgAccessControl; pgAdm = pgAdmin 4; DG = DataGrip; pgCtl = pgControl; BB = Bytebase; Tel = Teleport; l2pg = ldap2pg; pgb = pgbedrock; CNPG = CloudNativePG; TF = Terraform provider; pgperm = pg_permissions.

| Feature | pgAC | pgAdm | DG | pgCtl | BB | Tel | l2pg | pgb | CNPG | TF | pgperm | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Create/edit/delete login and group roles | Yes | Yes | Yes | Yes | No | Yes | Yes | Yes | Yes | Yes | No | BB roles are its own IAM, separate from DB users; Tel creates users on connect |
| Full role attributes (VALID UNTIL, CONNECTION LIMIT, BYPASSRLS, REPLICATION, CREATEDB/CREATEROLE) | ? | Yes | ? | Partial | No | ? | ? | Yes | Partial | ? | No | pgAC README only mentions login and inherit; pgCtl lists "attributes" without detail; CNPG exposes login, superuser, validUntil and more |
| Per-role / per-database config parameters (ALTER ROLE ... SET) | ? | Yes | ? | Yes | No | ? | ? | ? | ? | ? | No | pgCtl calls it "role and database overrides" |
| Membership with ADMIN / INHERIT / SET options per membership (PG 16+) | Partial | Yes | ? | Yes | No | ? | ? | ? | ? | ? | No | pgAC has a default-inherit switch for future memberships; per-membership options not described |
| Grant/revoke on db, schema, table, sequence, function | Yes | Yes | Yes | Yes | No | Yes | Yes | Partial | No | Yes | No | pgb only models read/write on schemas, tables, sequences; Tel needs v15.2+ for object permissions; BB does not touch DB-level grants |
| WITH GRANT OPTION and explicit grantor | ? | Yes | Yes | ? | No | ? | ? | ? | No | Yes | No | |
| Default privileges (ALTER DEFAULT PRIVILEGES) | Yes | ? | ? | Yes | No | ? | Yes | ? | No | Yes | No | |
| Column-level privileges | No | ? | ? | ? | No | ? | ? | ? | No | ? | ? | pgrights has a column-access view and editor; pgAdmin's table dialog docs do not mention it |
| Row-level security policies | No | Partial | ? | ? | No | ? | ? | ? | No | ? | ? | pgAdmin has enable/force RLS switches on the table; pgrights views and edits policies |
| Effective (inherited) access explanation | Yes | ? | ? | Yes | No | No | No | No | No | No | Partial | pgCtl walks membership, schema, object to final result; pgperm exposes an all-permissions view with a granted flag |
| Reverse lookup: "who can access this object" | ? | ? | ? | ? | No | No | No | No | No | No | Yes | pgAC API is role-centric (`/permissions/{role}/objects`) |
| Multi-object / bulk grant | Yes | Yes | ? | ? | No | ? | Yes | Yes | No | Partial | No | pgAdmin Grant Wizard picks arbitrary objects; pgb uses `schema.*`; TF grants all tables in a schema |
| SQL preview before applying | Yes | Yes | Yes | Yes | ? | ? | Yes | Yes | No | ? | No | l2pg/pgb print every statement |
| Dry-run / check mode | Yes | No | No | Partial | ? | ? | Yes | ? | No | ? | No | pgCtl is plan then apply; l2pg is dry by default |
| Safe role removal (reassign + drop owned) | Yes | Yes | ? | ? | No | Partial | Yes | ? | ? | Yes | No | Tel drops only when nothing depends on the user, else locks |
| Object ownership transfer as a standalone action | Partial | Yes | ? | Partial | No | No | ? | Yes | No | ? | No | pgAC only reassigns during deletion |
| Persistent audit history of changes | No | ? | ? | Yes | Yes | Yes | Partial | Partial | No | ? | No | l2pg/pgb only print SQL; BB stores in its metadata DB and can stream to stdout |
| Multi-user / RBAC for the tool itself | No | Yes | n/a | Yes | Yes | Yes | n/a | n/a | n/a | n/a | n/a | pgCtl: viewer / operator / admin; BB: workspace and project roles, custom roles |
| SSO (OIDC) for the tool | No | ? | n/a | Yes | Yes | Yes | n/a | n/a | n/a | n/a | n/a | |
| Access request + approval workflow | No | No | No | ? | Yes | Yes | No | No | No | No | No | BB: JIT flow is described as an Enterprise feature in one tutorial; Tel: full version is Enterprise |
| Time-bound / auto-expiring access | No | Partial | No | ? | Yes | Yes | No | No | No | No | No | pgAdmin only exposes password VALID UNTIL; BB and Tel revoke automatically |
| Periodic access review / recertification | No | No | No | ? | ? | Yes | No | No | No | No | No | Tel "Access Lists" with recurring renewal |
| Ephemeral per-session DB users | No | No | No | No | No | Yes | No | No | No | No | No | Tel modes keep / best_effort_drop |
| Declarative desired state | No | No | No | No | No | Partial | Yes | Yes | Yes | Yes | Partial | CNPG covers roles only; pgperm compares against a target table |
| Drift detection / reporting | No | No | No | ? | ? | No | Yes | Yes | Yes | ? | Yes | l2pg check mode (v5 docs) exits non-zero on pending changes; pgb and CNPG revert manual changes; pgperm diff function |
| Export / generate config from live DB | No | ? | ? | ? | ? | No | ? | Yes | No | ? | Partial | pgb `generate`; pgAdmin SQL tab shows per-object DDL only |
| Directory (LDAP/AD) group sync | No | ? | No | ? | ? | Partial | Yes | No | No | No | No | Tel maps SSO traits to DB roles |
| Data masking | No | No | No | No | Yes | No | No | No | No | No | No | outside privilege scope |
| pg_hba.conf view/edit | No | ? | ? | Yes | No | No | No | No | No | No | No | |
| Multiple servers / connections | No | ? | ? | Yes | Yes | Yes | n/a | n/a | n/a | n/a | n/a | pgAC is configured by one set of env vars |
| Generated password / reset with one-time display | ? | ? | ? | ? | No | ? | ? | Partial | Yes | ? | No | Neon, Aiven console generate passwords; pgb/CNPG read from env/Secret; CNPG supports pre-hashed values |
| Security labels | No | Yes | ? | ? | No | No | ? | ? | ? | ? | No | |
| Dependency view of a role before deletion | Yes | Partial | ? | ? | No | No | Partial | ? | ? | ? | No | pgAC has `/roles/{name}/dependencies` |

## 3. Prioritised gap list (value vs effort)

Ranked best value-for-effort first. Value: High/Med/Low. Effort: S (days), M (1-2 weeks), L (multi-week or new subsystem). Items 1-3 first need a quick code check because the README is silent.

| # | Gap | Value | Effort | Seen in | Rationale |
| --- | --- | --- | --- | --- | --- |
| 1 | Complete role attributes: VALID UNTIL, CONNECTION LIMIT, BYPASSRLS, REPLICATION, CREATEDB/CREATEROLE, role-level config parameters (verify what exists first) | High | S | pgAdmin, pgbedrock, CNPG, pgControl | Everyday admin fields; password expiry is the only native "temporary access" PostgreSQL has; cheap as the create/update form already exists |
| 2 | WITH GRANT OPTION and choosing the grantor (verify first) | Med | S | pgAdmin, DataGrip, Terraform provider | Delegated-grant setups need it; the generated SQL and allowlist change are small |
| 3 | Per-membership ADMIN / INHERIT / SET options (PG 16+) | Med | S-M | pgAdmin, pgControl | The README only has a default-inherit switch; the options are first-class in PG 16 and affect whether access is really effective |
| 4 | Persistent audit history: store actor, time, applied SQL and result in a table or file; filter in UI; optional JSON stdout export | High | M (S for a JSON-lines file or stdout only) | pgControl, Bytebase, Teleport | "Server log only" fails most compliance asks and is the main reason teams pick a governance panel over pgAdmin |
| 5 | Export and reporting: download roles, memberships and grants as a SQL script, YAML or CSV; "who can access this object" report | High | S-M | pgbedrock (generate), pg_permissions | Gives backup, migration and review evidence with almost no new UI; the set-based queries already exist |
| 6 | Multi-user RBAC for the app (viewer / operator / admin) plus optional OIDC SSO | High | M | pgControl, Bytebase, pgAdmin, Teleport | A single shared admin login is the biggest blocker for team use and for attributing audit entries to a person (pairs with #4) |
| 7 | Time-bound access: expiring memberships and grants, scheduled revoke, expiry reminders | High | M-L | Bytebase, Teleport | PostgreSQL has no native expiry for grants or membership, so it needs a metadata store and scheduler; high demand for contractor and break-glass use |
| 8 | Drift detection: save a snapshot or "expected" state and diff it against live state, with a "fix" plan | Med-High | M | pgbedrock, ldap2pg (check mode), CNPG, pg_permissions | Reuses the dry-run/SQL-preview machinery; turns the tool from a one-shot editor into a control that catches out-of-band changes |
| 9 | Column-level privileges | Med | M | pgrights | Common requirement for PII columns; needs a column-aware ACL query, UI, and effective-access logic |
| 10 | Ownership transfer action (ALTER ... OWNER TO / REASSIGN OWNED outside of deletion) | Low-Med | S | pgAdmin, pgbedrock, pgControl | Today the only ownership change is bundled with role deletion |
| 11 | Password UX: generator, one-time reveal, expiry nudges | Med | S | Neon, Aiven consoles, CNPG | Avoids admins typing weak passwords; client-side SCRAM hashing is already there |
| 12 | Multiple servers / connection profiles | Med | M | pgControl, Bytebase, Teleport | Real estates have several clusters; needs credential storage (encryption) and a server selector |
| 13 | Access request and approval workflow | Med | L | Bytebase, Teleport | Valuable only once #4, #6 and #7 exist; both reference tools gate the full flow behind enterprise plans, which signals its weight |
| 14 | Row-level security policy viewer, then editor | Med | M (view) / L (edit) | pgrights, pgAdmin (toggle only) | Common in Supabase-style stacks; a read-only list of policies per table is a cheap first step |
| 15 | Read-only pg_hba view (via the pg_hba_file_rules system view; general PostgreSQL knowledge, not from the surveyed sources) | Low-Med | S | pgControl (also edits) | Explains "why can't this user log in"; editing is risky and the README deliberately leaves it out |
| 16 | LDAP / directory group sync into roles | Med | L | ldap2pg, Teleport (via SSO traits) | Relevant to AD shops; consider integrating with ldap2pg instead of rebuilding |
| 17 | Periodic access review (recertification) | Low-Med | M | Teleport Access Lists | Depends on the metadata store from #4 and #7 |
| 18 | Notifications (webhook / Slack / email) on changes and expiries | Low-Med | S-M | Teleport (request plugins) | Cheap once audit events exist |
| 19 | Privileges on large objects, types, FDWs/servers, security labels | Low | S-M each | pgAdmin (labels) | README lists them as out of scope; rarely needed |
| 20 | Ephemeral per-session users, data masking | Low | L | Teleport, Bytebase | Belongs to access-proxy products; skip |

Suggested sequencing: 1-3 (quick wins) -> 4 + 6 (audit with identities) -> 5 -> 7 -> 8 -> 9.

## 4. What could not be verified

* DBeaver: no official page on PostgreSQL role/user management could be fetched, so it is left out of the matrix.
* Supabase dashboard: its Postgres Roles guide shows roles and grants as SQL only (the one dashboard mention is changing the postgres password); whether the dashboard has a roles/privileges screen is unconfirmed, so it is not in the matrix.
* Adminer, pgweb, AWS RDS and Cloud SQL consoles: nothing relevant found or not searched in depth.
* Terraform provider and Ansible modules: read only through search summaries, so most of their cells are "?".
* pgbedrock check mode: one summary said it exists, the project-goals page did not mention it; marked "?". l2pg `--check` appears in v5 docs but may have changed in v6.
* pgControl: everything comes from its Docker Hub page (vendor description); approvals, drift, export are simply not mentioned there. It is AGPL-3.0 and also ships Patroni and replication tooling beyond this app's scope.
* Bytebase JIT: one tutorial says the request workflow is Enterprise-only; plan tiers may have changed.
* pgAdmin: no page found on default-privileges editing or on column privileges; "?" does not mean absent.
* pgAccessControl itself: attribute coverage, GRANT OPTION, per-membership options and password generation were not stated in the README; confirm in the code before scoping items 1-3 and 11.
