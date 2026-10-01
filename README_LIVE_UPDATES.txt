VYBE LIVE ADMIN UPDATES

Replace your current app.py with the included app.py. Keep your existing render.yaml, database, environment variables, and other project files unchanged.

What changed:
- Added DB-backed live revision signal shared across Render/Gunicorn workers.
- Successful admin/publisher changes bump the revision automatically.
- Student pages check the tiny revision endpoint in the background.
- When content changes, only the page content is fetched/replaced; there is no full browser reload.
- Live chat is left on its own incremental chat loop.
- Forms are not overwritten while the student is actively editing.
- Added a small VYBE updated toast.

Deploy normally through GitHub/Render after replacing app.py.
