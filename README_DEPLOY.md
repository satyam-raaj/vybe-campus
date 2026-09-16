# VYBE public deployment

This package is prepared for a public VYBE beta using:
- Render Free Web Service for Flask
- Neon Free Postgres for persistent student/issue/community data
- Your existing Google Drive folder for the student Academics button

## Files
- `VYBE_PUBLIC.py` — production Flask app
- `requirements.txt` — Python dependencies
- `render.yaml` — Render service configuration
- `.python-version` — Python 3.13

## 1. Create the database
1. Create a free Neon account and a new Postgres project.
2. Copy the connection string (`postgresql://...`).
3. Keep it private; it becomes the `DATABASE_URL` secret in Render.

## 2. Put these files in a GitHub repository
Upload the four files above to a private GitHub repo, for example `vybe`.
Do NOT upload passwords, database URLs, or student data.

## 3. Deploy on Render
1. Create a Render account.
2. New -> Web Service -> connect the GitHub repo.
3. Render can use `render.yaml`, or set:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn VYBE_PUBLIC:app`
   - Plan: Free
4. Add environment variables:
   - `DATABASE_URL` = your Neon connection string
   - `VYBE_ADMIN_PASSWORD` = a strong admin password
   - `VYBE_SECRET_KEY` = a long random secret
   - `VYBE_DRIVE_URL` = the existing VYBE Google Drive folder URL

## 4. First launch
The app creates its PostgreSQL tables automatically on first startup.

## 5. Test before sharing
- Student registration -> pending -> admin approval
- Student login uses Name + Student ID only
- Student IDs remain private from other students
- Community solutions appear immediately
- Only the reporter sees "Accept solution & delete chat", and only after a solution exists
- Accepting deletes the issue and its solution chat
- Admin can approve/block/unblock students
- Admin can delete one student or all student data
- Academics -> Google Drive works

## Important free-tier notes
Render Free is suitable for a beta/hobby deployment but has sleep/usage limitations.
Neon's Free plan has usage limits and can scale to zero. Monitor usage before treating this as a permanent college production system.

## Custom domain later
Once VYBE is live on its Render `onrender.com` address, buy your preferred domain and add it to the Render service's Custom Domains section. Render provides HTTPS for custom domains.
