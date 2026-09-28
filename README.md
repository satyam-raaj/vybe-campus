# VYBE 2.0 build

This package is based on the existing VYBE Flask application and adds the VYBE 2.0 foundation.

## Included

- Student experience foundation
- Faculty accounts and faculty portal
- Faculty resource uploads
- University Help Desk and admin ticket management
- Campus Clubs and membership
- Campus calendar using existing Events
- Emergency campus alerts
- Account security/session foundation
- University and department schema foundation for future multi-university isolation
- Privacy Policy and Terms & Conditions draft pages
- Custom VYBE favicon
- Production launch gate
- Restrained dark blue/black UI with no purple gradients, fake metrics, fake reviews, emoji iconography, cursor animations, or pill-shaped buttons
- No external college website ingestion option in the new product surface

## Launch lock

`VYBE_LAUNCH_READY=0` is intentional. Do not set it to `1` until:

1. The final custom domain is connected and HTTPS is working.
2. The favicon is visible on that domain.
3. Any platform-generated "made with AI" branding is removed.
4. The Privacy Policy and Terms & Conditions have been reviewed and finalized by the deploying institution.
5. All major routes, permissions, uploads, authentication and mobile layouts have been tested.
6. Production secrets and database backups are configured.
7. A final smoke test is completed.

## Run locally

```bash
python -m pip install -r requirements.txt
set VYBE_LAUNCH_READY=0
python vybe_app.py
```

For a production deployment, configure the environment variables from `.env.example` in the hosting provider.

## Important

The custom domain cannot be registered or connected by this source package itself. That is a DNS/hosting step. The launch gate is intentionally kept closed until that external step is completed.
