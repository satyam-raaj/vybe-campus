# VYBE public deployment

This repository contains the current VYBE Flask application prepared for
Render + PostgreSQL/Supabase deployment.

## Files

- `app.py` — current production Flask application
- `requirements.txt` — Python dependencies
- `render.yaml` — Render build/start/health configuration
- `.python-version` — Python version

## Database

VYBE uses the PostgreSQL database supplied through the `DATABASE_URL`
environment variable.

For the current deployment, use your **Supabase PostgreSQL connection string**
as Render's `DATABASE_URL`.

Do **not** restore or reset the existing database. The application performs
schema creation/migration with `CREATE TABLE IF NOT EXISTS` and
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`.

## Render setup

The included `render.yaml` uses:

- Build: `pip install -r requirements.txt`
- Start: `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`
- Health check: `/healthz`

Set these Render environment variables:

### Required

- `DATABASE_URL` — the PostgreSQL connection string from Supabase
- `VYBE_SECRET_KEY` — a long random secret; the Render blueprint can generate it
- `VYBE_ADMIN_INITIAL_PASSWORD` — only for initial admin setup if the database
  does not already contain an admin password

### Optional

- `VYBE_PASSKEY_RP_ID`
- `VYBE_PASSKEY_ORIGIN`
- `VYBE_AI_API_KEY`
- `VYBE_AI_ENDPOINT`
- `VYBE_AI_MODEL`

Never commit real passwords, database URLs, API keys, passkeys, or student data.

## Deployment order

1. Confirm the Supabase database already contains the migrated VYBE data.
2. Deploy this repository to Render.
3. In Render, set `DATABASE_URL` to the **Supabase PostgreSQL connection string**.
4. Set `VYBE_SECRET_KEY`.
5. Set `VYBE_ADMIN_INITIAL_PASSWORD` only if initial admin setup is required.
6. Deploy/redeploy.
7. Open `/healthz` and confirm the service reports healthy.
8. Test admin login, student registration/login, existing data, community,
   academics, events, and the Global VYBE Online/Offline control.
9. Only after testing should VYBE be made publicly available.

## Global Online / Offline control

The admin panel contains the VYBE Public Status control.

- Offline: public/student routes are blocked while admin access remains available.
- Online: normal student/public access is restored.

This status is stored in the database and is not a database reset.

## Important

The application must receive a valid PostgreSQL `DATABASE_URL` at startup.
If Render still points to an old Render/Neon/internal PostgreSQL service, the
application will connect to that service instead of Supabase.

A PostgreSQL error such as:

`role "..." is not permitted to log in`

indicates a database credential/role problem in the configured `DATABASE_URL`;
it is not fixed by restoring the VYBE database or changing the Flask routes.
