# VYBE final academic-portal build

This package replaces the old VYBE application files with one `app.py` plus the deployment files required by Render.

## What changed

- VYBE keeps its existing student, community, campus, timetable, announcements, events, profile, admin, password reset, passkey, resources and VYBE AI functionality.
- Academic Hub is integrated into the student experience.
- Academic resources follow the supplied reference-site structure: Study Notes, Study Materials, SLM/PDF resources, Previous Year Papers, Results, Date Sheets, Admit Cards, Exam Forms, Online Classes, Recorded Lectures, E-Books, Academic Portals, Academic Search and Updates.
- Student dashboard is reorganized around academic access plus VYBE's unique AI, Community, Campus Help Desk, Timetable, Announcements and Events features.
- UI uses a clean white/black/green/blue/grey system inspired by the supplied screenshots.
- Emoji-style navigation glyphs were removed.
- A SQLite migration bug that could execute PostgreSQL-style `BYTEA` syntax on SQLite was removed.
- PostgreSQL startup migration for legacy admin login-log `success` types was made safer.
- The source compiles and the SQLite database initializer was run twice successfully to verify idempotent startup schema creation.

## Render

Use `app.py` as the application entry point. The included `render.yaml` uses Gunicorn.

Keep your existing Render environment variables, especially `DATABASE_URL` and `VYBE_SECRET_KEY`.

The code was statically checked in this environment. A live Render deployment cannot be executed from this environment, so after pushing, check the Render deploy log once.
