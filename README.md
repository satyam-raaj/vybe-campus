# VYBE Campus — fixed Vercel + Neon + Google Drive build

This package fixes the deployment/runtime problems in the supplied VYBE project.

## What was fixed

- **Google Drive uploads:** supports `VYBE_GOOGLE_SERVICE_ACCOUNT_JSON` and a safer base64 form, `VYBE_GOOGLE_SERVICE_ACCOUNT_JSON_B64`.
- **Drive permissions:** uploads no longer fail just because Google Workspace blocks public sharing.
- **Private Drive delivery:** student documents are streamed from Google Drive through an authenticated VYBE route, so students do not need access to the Drive folder.
- **Fresh Neon bug:** the Drive timetable path no longer inserts `NULL` into the old `timetables.file_name NOT NULL` column.
- **Drive diagnostics:** Admin → Settings → Drive now has **Test Drive connection**.
- **Custom errors:** 500-class errors use the standalone VYBE error page without depending on the normal database/layout renderer.
- **Readiness:** `/readyz` checks database connectivity and reports whether Drive credentials are configured.
- **Vercel:** keeps the current zero-configuration Flask deployment model. Vercel currently supports Flask without an `/api` wrapper or custom redirect configuration.
- **Python runtime:** pinned to Python 3.12 for predictable Vercel deployments.

Vercel's current Flask deployment model is zero-configuration, so `app.py` can remain at the project root. See the official Vercel Flask guidance before deploying.

## Required Vercel environment variables

Set these in **Vercel → Project → Settings → Environment Variables** for Production (and Preview if you use it):

```text
DATABASE_URL=<your Neon PostgreSQL connection string>
VYBE_SECRET_KEY=<long random secret>
VYBE_ADMIN_INITIAL_PASSWORD=<initial admin password>
```

For Neon, use the **pooled connection URI** when available. Neon provides pooled connection URIs with the `-pooler` endpoint.

### Google Drive

Create/use a Google Cloud service account with the Google Drive API enabled.

Share the **root VYBE Google Drive folder** with the service account's `client_email` as Editor.

Then set ONE of:

```text
VYBE_GOOGLE_SERVICE_ACCOUNT_JSON=<complete service-account JSON>
```

or

```text
VYBE_GOOGLE_SERVICE_ACCOUNT_JSON_B64=<base64 of the complete service-account JSON>
```

Also set:

```text
VYBE_DRIVE_ROOT_FOLDER_ID=<the root Drive folder ID>
VYBE_DRIVE_PUBLIC_FILES=0
```

`VYBE_DRIVE_PUBLIC_FILES=0` is recommended because the fixed app streams files through VYBE instead of requiring public Drive sharing.

The existing folder ID in the original project is kept as the default, but set the variable explicitly if your folder is different.

### Passkeys

After Vercel gives you the production hostname:

```text
VYBE_PASSKEY_RP_ID=your-production-hostname.vercel.app
VYBE_PASSKEY_ORIGIN=https://your-production-hostname.vercel.app
```

If you later attach a custom domain, update both values to that domain.

## Deploy

1. Replace the old project files with this package.
2. Push to GitHub / your connected Vercel repository.
3. Confirm the Vercel environment variables above.
4. Redeploy.
5. Open:
   - `/healthz` — database health
   - `/readyz` — database + Drive configuration check
6. Log into Admin → Settings → Drive.
7. Click **Test Drive connection**.
8. Upload one small PDF.
9. Log in as a student and open the document.

## Important Google Drive step

A normal personal Google Drive account is not automatically accessible to a service account. The root folder must be explicitly shared with the service account email. If your Google Workspace administrator blocks service-account access or external sharing, the Drive test will report the Google API error instead of silently buffering/failing.

## Why the site was buffering

The original app created fresh Neon connections repeatedly and also depended on Drive/API operations that could sit behind a long timeout. The fixed build reduces unnecessary online-status database checks, uses the Neon connection URI directly, and moves large student file delivery to streaming rather than redirecting users to a private Drive URL.

## Notes

- Neon stores application/database metadata.
- Google Drive stores uploaded academic files.
- Vercel's filesystem should not be treated as permanent storage.
- Do not commit service-account JSON, `.env` files, or database credentials to Git.
