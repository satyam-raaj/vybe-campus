# VYBE — Vercel + Neon build

This build is for Vercel Flask Functions with Neon PostgreSQL.

## Important
Replace the existing GitHub `app.py`, `requirements.txt`, and `vercel.json` with the files in this package before redeploying.

The previous deployment failed because the old `app.py` tried to create `vybe_uploads` inside Vercel's read-only `/var/task` directory. This build does not write uploaded resources to the deployment filesystem; uploaded resource bytes are stored in PostgreSQL.

Required Vercel environment variables:
- `DATABASE_URL` — Neon PostgreSQL connection string
- `VYBE_SECRET_KEY` — your VYBE session secret
- `VYBE_ADMIN_INITIAL_PASSWORD` — initial admin password

After Vercel assigns the production domain, set:
- `VYBE_PASSKEY_RP_ID` — production hostname only, e.g. `vybe-campus.vercel.app`
- `VYBE_PASSKEY_ORIGIN` — full HTTPS origin, e.g. `https://vybe-campus.vercel.app`
