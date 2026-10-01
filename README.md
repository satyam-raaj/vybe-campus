# VYBE — Restored Build

This package restores the VYBE V14 application source without the experimental Socket.IO/gevent performance rewrite.

## Render
- Build: `pip install -r requirements.txt`
- Start: `gunicorn --workers 1 --threads 8 --timeout 120 app:app`
- Required environment variable: `DATABASE_URL` pointing to the Supabase PostgreSQL database.
- Keep the existing VYBE secret/passkey environment variables from the working deployment.
