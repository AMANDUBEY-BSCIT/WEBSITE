# BookBridge — Donate, Exchange & Discover Books

A Flask, Jinja2 and SQLite community book-sharing website for browsing, donating, requesting, exchanging and finding affordable second-hand books. There are no seeded listings or accounts; the database starts empty and fills as members use the site. BookBridge does not process payments. Readers arrange any payment or hand-off directly.

## Requirements

- Windows 10 or 11
- Python 3.10 or newer from [python.org](https://www.python.org/downloads/). During installation, enable **Add python.exe to PATH**.

## Install and run in Windows PowerShell

Open the BookBridge folder in VS Code. In the menu choose **Terminal → New Terminal**. Install the dependencies once:

```powershell
py -m pip install -r requirements.txt
```

Then start the site with:

```powershell
py app.py
```

The first start automatically creates a local `.env` with a randomly generated secret key. That key is reused on subsequent starts, so login sessions and cookies remain valid across restarts. `.env` and the local SQLite database are excluded from Git. Keep the terminal open while using the site, open **http://127.0.0.1:5000** in your browser, and press `Ctrl+C` to stop the server.

If the `py` launcher is unavailable, install Python from [python.org](https://www.python.org/downloads/) and enable **Add python.exe to PATH** during installation.

## Temporary public link (Cloudflare Tunnel)

With the project dependencies installed and `cloudflared` available at `C:\Program Files (x86)\cloudflared\cloudflared.exe`, start a temporary public HTTPS link from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\start_public.ps1
```

The script reuses a Python `app.py` already listening on port 5000, or starts the app in a separate window. It then prints the generated `https://....trycloudflare.com` address. If dependencies are missing, install them with `py -m pip install -r requirements.txt`; if port 5000 belongs to another program, stop that program before retrying.

Keep the PC, Flask window and tunnel window running while the link is in use. This temporary address can change when the tunnel restarts. Anyone with the link can reach the public parts of the site, so do not share it with people you do not trust. Press `Ctrl+C` in the tunnel window to stop public access; stop Flask separately in its window.

## Administrator access

The admin role is stored in the existing `users.is_admin` database field and checked on the server for every admin route. Do not set admin access from a website form or by adding an email to source code. The designated administrator must first have an active, existing BookBridge account. The one-time Flask CLI command below only promotes the exact designated email; it does not create an account, change a password, or reveal credentials:

```powershell
py -m flask --app app grant-initial-admin --confirm-email dubeyaman4039@gmail.com
```

The current app does not implement email verification, so verify control of that email address through your existing account-verification process before running this command. Sign in using the account's existing password, or use BookBridge's password-reset flow. The admin dashboard is available at `/admin`; the restricted support queue is at `/admin/support-tickets`.

### Registered users and local export

Only the designated administrator account can open `/admin/users` or member detail pages. The page supports name/email search, active/suspended filtering, listing counts and account suspension/reactivation. Login and registration provide accessible show/hide password controls; registration also checks password confirmation and requires at least 8 characters using at least three character types.

The current configured database file is `instance\bookbridge.sqlite3` (absolute path: `C:\Users\AMIT\Documents\AMAN\CEP\instance\bookbridge.sqlite3`). `DATABASE_PATH` can override this location. User passwords remain secure hashes and are never included in the user page or CSV.

To explicitly generate the password-free registered-user CSV from the project folder, run this in the VS Code PowerShell terminal:

```powershell
py -m flask --app app export-registered-users --confirm-email dubeyaman4039@gmail.com
```

The command prompts for the designated administrator's existing password with terminal input hidden; it does not accept the password as a command-line argument. The export is saved beside the configured database in `admin_exports\registered_users.csv` (for the current database: `instance\admin_exports\registered_users.csv`). The export directory is excluded from Git and is not served by Flask. The command does not run automatically during normal site startup.

Starting the app runs additive SQLite schema migrations automatically. Existing users, books, support tickets, replies, and passwords are preserved. The migration adds listing moderation state and private admin support notes, and safely expands existing ticket status constraints to include `Closed`.

## Password reset email setup (Gmail SMTP)

Password reset codes are sent by SMTP; the app does not show codes on the site or in its logs. To send them through Gmail:

1. Turn on 2-Step Verification for the Google account that will send the messages.
2. Create a Google **App Password** for BookBridge in the Google Account security settings. Use this app password only for SMTP. Do not use or enter your normal Gmail password; this feature resets only a BookBridge account password.
3. Add these settings to the existing project `.env` file without removing its generated `SECRET_KEY`:

   ```dotenv
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your-sender@gmail.com
   SMTP_PASSWORD=your-16-character-google-app-password
   SMTP_FROM_EMAIL=your-sender@gmail.com
   ```

   Replace the example values. Keep `.env` private and do not commit or share it. `SMTP_FROM_EMAIL` may be omitted to use `SMTP_USERNAME`.
4. Restart the app with `py app.py`. Create or use a BookBridge account whose registered email you can access, open **Forgot password?** from Login, request a code, and verify that the message arrives. Until valid SMTP settings are configured and delivery is tested, the app does not claim that an email was sent.

Reset codes are random 6-digit values stored as keyed hashes, expire after 5 minutes, and allow at most 5 verification attempts. Requests have a 60-second resend cooldown and per-email/per-IP hourly limits. SMTP failures are recorded only as a generic server log message; the site response does not reveal whether an email belongs to an account.

Run the automated workflow tests with:

```powershell
py -m unittest discover -s tests -v
```

The automated SMTP tests use a mock mail server. Test real delivery separately by configuring the Gmail settings above and requesting a reset for an account email you can access.

## Features

- Public book browsing, search and category, condition, listing-type and location filters
- Account signup and login with Werkzeug password hashing
- Email-delivered, expiring one-time password reset codes
- CSRF protection for POST forms, server-side validation and private account pages
- Free donation, affordable sale, book requests and book-for-book exchange listings
- Optional validated book photos and image attachments for requests and enquiries
- Required book condition selection from New through Damaged
- Exchange offer acceptance/rejection and status tracking
- Owner enquiries and a personal dashboard
- Private buyer-seller conversations linked to enquiries, with message history and unread counts
- Under-₹50, Under-₹100 and Under-₹200 views
- Database-backed administrator role and restricted admin routes
- Admin dashboard and member dashboard with live database metrics, searchable user/listing management, listing approval/rejection/editing/removal, request moderation, and an administrator action log
- Private customer support queue with Open, In Progress, Resolved, and Closed states, searchable tickets, customer-visible replies, and admin-only internal notes
- Participant-reported private messages with admin review/removal limited to reported messages; administrators do not receive general access to private conversations
- Public, searchable Help Center with feature guides and troubleshooting steps
- Private, persistent customer support tickets and replies, with admin-only ticket management
- SQLite database created automatically at `instance/bookbridge.sqlite3`
- Uploaded images stored at `instance/uploads` by default; set `UPLOAD_FOLDER` to a persistent location for deployment

## Project structure

```text
BookBridge/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── instance/                 # SQLite database and uploaded images persist here
│   └── uploads/              # Generated at runtime; ignored by Git
├── static/
│   ├── css/style.css
│   └── js/script.js
└── templates/                # Jinja2 pages and shared template fragments
```

For a presentation, create a normal member account, add a book, then browse and inspect its details. To demonstrate an exchange, create exchange listings with two accounts. No demonstration records are silently inserted.

## Help Center and customer support

The public Help Center is available at `/help`. Signed-in members can submit and follow private support tickets from `/support` and `/support/tickets`; an administrator can review and reply to tickets at `/admin/support-tickets`. Admin-only internal notes are not shown to customers. Ticket schema updates preserve existing ticket and reply records. Members can report a community safety concern by choosing its support category. Book requests currently have no built-in member reply/contact workflow.

For deployment beyond your own computer, use a production WSGI server, HTTPS, a private stable secret key, secure cookie settings, backups and appropriate abuse controls. The built-in Flask development server is for local demonstration only.
