# HEXZA TOOLS

Dark dashboard with three separate tools and three separate Discord webhooks.

## Features
- Cookie security checklist (does not collect authentication cookies)
- Nontrue format diagnostics: username syntax, numeric user ID, Roblox profile URL format/ID match, IP format and public IP country lookup
- Bulk TXT/CSV import (CSV headers: `username,user_id,ip_address,profile_url`; max 100 rows)
- Separate Discord webhook settings for each tool
- Per-record Discord embeds and a bulk TXT attachment
- Password field is always `[REDACTED / NOT COLLECTED]`; passwords, cookies, session tokens and recovery codes are not accepted, tested, stored or exported

## Setup (Windows CMD)

1. Install Python 3.10+.
2. Open CMD in this folder.
3. Install dependencies:

   `py -m pip install -r requirements.txt`

4. Set an admin key (use a long random value):

   `set "HEXZA_ADMIN_KEY=replace-with-a-long-random-admin-key"`

5. Start:

   `py app.py`

6. Open `http://127.0.0.1:5000`.
7. Open Webhook Settings, enter the admin key, then configure each Discord webhook separately.

Webhook URLs are held in backend memory only and are cleared when the server restarts. Re-enter them after restarting. Never publish the webhook URLs or expose this development server directly to the internet.

## Important notes
- Public IP country lookup sends the supplied public IP address to `ipapi.co`. Do not submit IP addresses unless you have permission to process them.
- IP geolocation is approximate and does not establish a person's actual location.
- The checker validates data formats; it does not log into Roblox, validate passwords, determine private login methods, or bypass account security.
- Before any public deployment, use HTTPS, a production WSGI server, admin authentication, CSRF protection, rate limiting, and secure secret management.