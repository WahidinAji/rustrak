---
"@rustrak/server": patch
---

Sign in through any OpenID Connect provider, configured with `OIDC_*` and off by default; linking an existing account asks for its password once (@GhaziBenDahmane). Resolve an event by the ID a Sentry SDK returned, through `GET /api/projects/{id}/events/sentry/{event_id}` and `events.getBySentryId` in the client (@jav-ed). Quotas are enforced exactly in fixed minute and hour windows, 429s carry `X-Sentry-Rate-Limits`, the default limits are raised, a project can set lower limits of its own, and dropped events are counted per project. The account page gains a timezone picker, breadcrumb timestamps are read with Relay's grammar, and `docker-compose.yml` runs one SQLite container with PostgreSQL moved to `docker-compose.postgres.yml`.
