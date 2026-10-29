import csv
import hmac
import io
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
import uuid
import warnings
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

import click
from dotenv import load_dotenv
from flask import Flask, abort, flash, g, redirect, render_template, request, send_from_directory, session, url_for
from PIL import Image, ImageSequence, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
ENV_FILE = BASE_DIR / ".env"
DATABASE = Path(os.environ.get("DATABASE_PATH", INSTANCE_DIR / "bookbridge.sqlite3"))
UPLOAD_MAX_BYTES = 10 * 1024 * 1024
UPLOAD_EXTENSIONS = {
    ".jpg": ("JPEG", "image/jpeg"),
    ".jpeg": ("JPEG", "image/jpeg"),
    ".png": ("PNG", "image/png"),
    ".webp": ("WEBP", "image/webp"),
    ".gif": ("GIF", "image/gif"),
    ".bmp": ("BMP", "image/bmp"),
}
UPLOAD_MIME_ALIASES = {"image/x-ms-bmp": "image/bmp"}


def load_secret_key(env_file=ENV_FILE):
    if not env_file.exists():
        try:
            with env_file.open("x", encoding="utf-8") as secret_file:
                secret_file.write(f"SECRET_KEY={secrets.token_hex(32)}\n")
        except FileExistsError:
            pass
    load_dotenv(dotenv_path=env_file)
    return os.environ.get("SECRET_KEY")


SECRET_KEY = load_secret_key()
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Add it to .env or set the environment variable.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=str(DATABASE),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=UPLOAD_MAX_BYTES + 256 * 1024,
    UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", str(INSTANCE_DIR / "uploads")),
)

CATEGORIES = ["Academic", "Fiction", "Novels", "Non-fiction", "Competitive Exams", "Technology", "Children", "Other"]
CONDITIONS = ["New", "Like New", "Very Good", "Good", "Acceptable", "Heavily Used", "Damaged"]
LISTING_TYPES = {"donation", "sale", "exchange"}
SUPPORT_CATEGORIES = (
    "Account and login",
    "Book listing",
    "Book request",
    "Exchange",
    "Buyer-seller messages",
    "Safety concern",
    "Website problem",
    "Other",
)
SUPPORT_STATUSES = ("Open", "In Progress", "Resolved", "Closed")
INITIAL_ADMIN_EMAIL = "dubeyaman4039@gmail.com"
PASSWORD_RESET_CODE_TTL = 5 * 60
PASSWORD_RESET_GRANT_TTL = 10 * 60
PASSWORD_RESET_MAX_ATTEMPTS = 5
PASSWORD_RESET_RESEND_COOLDOWN = 60
PASSWORD_RESET_EMAIL_LIMIT = 5
PASSWORD_RESET_IP_LIMIT = 20
PASSWORD_RESET_GENERIC_MESSAGE = (
    "If an account exists for this email, a reset code will be sent if email delivery is "
    "configured and succeeds. If it does not arrive, contact the site administrator."
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _password_reset_digest(purpose, identifier, value):
    message = f"{purpose}:{identifier}:{value}".encode("utf-8")
    return hmac.new(app.config["SECRET_KEY"].encode("utf-8"), message, "sha256").hexdigest()


def _password_reset_rate_key(kind, value):
    return _password_reset_digest("rate-limit", kind, value)


def _allow_password_reset_request(email, remote_address):
    now = time.time()
    database = get_db()
    database.execute("BEGIN IMMEDIATE")
    database.execute(
        "DELETE FROM password_reset_rate_limits WHERE window_started_at < ?",
        (now - 3600,),
    )
    keys = (
        ("email", _password_reset_rate_key("email", email), PASSWORD_RESET_EMAIL_LIMIT),
        ("ip", _password_reset_rate_key("ip", remote_address or "unknown"), PASSWORD_RESET_IP_LIMIT),
    )
    rows = {
        row["rate_key"]: row
        for row in database.execute(
            "SELECT rate_key, window_started_at, request_count, last_requested_at "
            "FROM password_reset_rate_limits WHERE rate_key IN (?, ?)",
            (keys[0][1], keys[1][1]),
        ).fetchall()
    }
    email_row = rows.get(keys[0][1])
    if email_row and (
        now - email_row["last_requested_at"] < PASSWORD_RESET_RESEND_COOLDOWN
        or email_row["request_count"] >= keys[0][2]
    ):
        database.commit()
        return False
    ip_row = rows.get(keys[1][1])
    if ip_row and ip_row["request_count"] >= keys[1][2]:
        database.commit()
        return False

    for _kind, key, _limit in keys:
        row = rows.get(key)
        if row and now - row["window_started_at"] < 3600:
            database.execute(
                "UPDATE password_reset_rate_limits SET request_count = request_count + 1, "
                "last_requested_at = ? WHERE rate_key = ?",
                (now, key),
            )
        else:
            database.execute(
                "INSERT INTO password_reset_rate_limits "
                "(rate_key, window_started_at, request_count, last_requested_at) "
                "VALUES (?, ?, 1, ?) ON CONFLICT(rate_key) DO UPDATE SET "
                "window_started_at = excluded.window_started_at, request_count = 1, "
                "last_requested_at = excluded.last_requested_at",
                (key, now, now),
            )
    database.commit()
    return True


def send_password_reset_email(recipient, otp):
    host = os.environ.get("SMTP_HOST", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM_EMAIL", "").strip() or username
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
    except ValueError as error:
        raise RuntimeError("SMTP_PORT must be a valid port number.") from error
    if not host or not username or not password or not sender:
        raise RuntimeError("SMTP_HOST, SMTP_USERNAME, and SMTP_PASSWORD must be configured.")

    message = EmailMessage()
    message["Subject"] = "Your BookBridge password reset code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your BookBridge password reset code is {otp}.\n\n"
        "Enter this code on the password reset page within 5 minutes. "
        "If you did not request a password reset, you can ignore this email."
    )
    with smtplib.SMTP(host, port, timeout=10) as mail_server:
        mail_server.ehlo()
        mail_server.starttls(context=ssl.create_default_context())
        mail_server.ehlo()
        mail_server.login(username, password)
        mail_server.send_message(message)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(app.config["DATABASE"], timeout=10) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                condition TEXT NOT NULL,
                location TEXT NOT NULL,
                price REAL NOT NULL DEFAULT 0 CHECK(price >= 0),
                listing_type TEXT NOT NULL CHECK(listing_type IN ('donation', 'sale', 'exchange')),
                is_active INTEGER NOT NULL DEFAULT 1,
                moderation_status TEXT NOT NULL DEFAULT 'approved',
                image_filename TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS book_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                location TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                attachment_filename TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exchange_offers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                book_id INTEGER NOT NULL REFERENCES books(id),
                offered_book_id INTEGER NOT NULL REFERENCES books(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                message TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'rejected')),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                book_id INTEGER NOT NULL REFERENCES books(id),
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                message TEXT NOT NULL,
                attachment_filename TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enquiry_id INTEGER NOT NULL REFERENCES enquiries(id) ON DELETE CASCADE,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                read_at TEXT,
                is_hidden INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS message_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                reporter_id INTEGER NOT NULL REFERENCES users(id),
                reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK(status IN ('Open', 'Reviewed', 'Removed')),
                created_at TEXT NOT NULL,
                UNIQUE(message_id, reporter_id)
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                category TEXT NOT NULL CHECK(category IN (
                    'Account and login', 'Book listing', 'Book request', 'Exchange',
                    'Buyer-seller messages', 'Safety concern', 'Website problem', 'Other'
                )),
                subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 120),
                description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 5000),
                book_id INTEGER REFERENCES books(id) ON DELETE SET NULL,
                status TEXT NOT NULL DEFAULT 'Open'
                    CHECK(status IN ('Open', 'In Progress', 'Resolved', 'Closed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS support_ticket_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 5000),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS support_ticket_internal_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
                admin_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 5000),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_action_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL REFERENCES users(id),
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                otp_hash TEXT,
                expires_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verification_hash TEXT,
                verification_expires_at REAL,
                UNIQUE(user_id)
            );
            CREATE TABLE IF NOT EXISTS password_reset_rate_limits (
                rate_key TEXT PRIMARY KEY,
                window_started_at REAL NOT NULL,
                request_count INTEGER NOT NULL,
                last_requested_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_books_active_type ON books(is_active, listing_type);
            CREATE INDEX IF NOT EXISTS idx_requests_active ON book_requests(is_active);
            CREATE INDEX IF NOT EXISTS idx_exchange_book ON exchange_offers(book_id, status);
            CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(enquiry_id, id);
            CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(recipient_id, read_at);
            CREATE INDEX IF NOT EXISTS idx_message_reports_status ON message_reports(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_admin_action_logs_created ON admin_action_logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_support_tickets_user ON support_tickets(user_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON support_tickets(status, updated_at);
            CREATE INDEX IF NOT EXISTS idx_support_ticket_messages ON support_ticket_messages(ticket_id, id);
            CREATE INDEX IF NOT EXISTS idx_support_ticket_notes ON support_ticket_internal_notes(ticket_id, id);
            CREATE INDEX IF NOT EXISTS idx_password_reset_expiry ON password_reset_tokens(expires_at);
            """
        )
        for table, column in (
            ("books", "image_filename"),
            ("book_requests", "attachment_filename"),
            ("enquiries", "attachment_filename"),
        ):
            existing_columns = {
                row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if column not in existing_columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
        book_columns = {
            row[1] for row in db.execute("PRAGMA table_info(books)").fetchall()
        }
        if "moderation_status" not in book_columns:
            db.execute(
                "ALTER TABLE books ADD COLUMN moderation_status TEXT NOT NULL DEFAULT 'approved'"
            )
        request_columns = {
            row[1] for row in db.execute("PRAGMA table_info(book_requests)").fetchall()
        }
        if "moderation_status" not in request_columns:
            db.execute(
                "ALTER TABLE book_requests ADD COLUMN moderation_status TEXT NOT NULL DEFAULT 'approved'"
            )
        message_columns = {
            row[1] for row in db.execute("PRAGMA table_info(messages)").fetchall()
        }
        if "is_hidden" not in message_columns:
            db.execute(
                "ALTER TABLE messages ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0"
            )

        ticket_schema = db.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'support_tickets'"
        ).fetchone()[0]
        if "'Closed'" not in ticket_schema:
            db.commit()
            db.execute("PRAGMA foreign_keys = OFF")
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """CREATE TABLE support_tickets_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        category TEXT NOT NULL CHECK(category IN (
                            'Account and login', 'Book listing', 'Book request', 'Exchange',
                            'Buyer-seller messages', 'Safety concern', 'Website problem', 'Other'
                        )),
                        subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 120),
                        description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 5000),
                        book_id INTEGER REFERENCES books(id) ON DELETE SET NULL,
                        status TEXT NOT NULL DEFAULT 'Open'
                            CHECK(status IN ('Open', 'In Progress', 'Resolved', 'Closed')),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )"""
                )
                db.execute(
                    """INSERT INTO support_tickets_new
                       (id, user_id, name, email, category, subject, description, book_id,
                        status, created_at, updated_at)
                       SELECT id, user_id, name, email, category, subject, description, book_id,
                              status, created_at, updated_at FROM support_tickets"""
                )
                db.execute("DROP TABLE support_tickets")
                db.execute("ALTER TABLE support_tickets_new RENAME TO support_tickets")
                db.commit()
            except sqlite3.Error:
                db.rollback()
                raise
            finally:
                db.execute("PRAGMA foreign_keys = ON")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_support_tickets_status "
            "ON support_tickets(status, updated_at)"
        )


def sync_registered_users_csv():
    export_directory = BASE_DIR / "private_exports"
    output_path = export_directory / "registered_users.csv"
    temporary_path = export_directory / ".registered_users.csv.tmp"
    try:
        export_directory.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(app.config["DATABASE"], timeout=10)
        try:
            users = database.execute(
                """SELECT id, name, email, created_at, is_admin, is_active
                   FROM users ORDER BY id"""
            ).fetchall()
        finally:
            database.close()
        with temporary_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(
                (
                    "User ID", "Full Name", "Email Address",
                    "Registration Date and Time", "Account Role", "Account Status",
                )
            )
            writer.writerows(
                (
                    user[0], user[1], user[2], user[3],
                    "Admin" if user[4] else "User",
                    "Active" if user[5] else "Suspended",
                )
                for user in users
            )
        try:
            os.chmod(export_directory, 0o700)
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        temporary_path.replace(output_path)
        return True
    except (OSError, sqlite3.Error):
        app.logger.exception("Could not synchronize the private registered users CSV.")
        temporary_path.unlink(missing_ok=True)
        return False


@app.cli.command("grant-initial-admin")
@click.option(
    "--confirm-email",
    required=True,
    help="Confirm the exact pre-existing account email before granting admin access.",
)
def grant_initial_admin(confirm_email):
    """Grant admin access to the one designated, already-registered account."""
    if confirm_email.strip().casefold() != INITIAL_ADMIN_EMAIL.casefold():
        raise click.ClickException("Only the designated BookBridge admin account can be promoted.")
    database_path = app.config["DATABASE"]
    with sqlite3.connect(database_path, timeout=10) as db:
        db.execute("PRAGMA foreign_keys = ON")
        account = db.execute(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE AND is_active = 1",
            (INITIAL_ADMIN_EMAIL,),
        ).fetchone()
        if not account:
            raise click.ClickException(
                "The designated account must be registered and active before it can be promoted."
            )
        db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (account[0],))
        db.commit()
    sync_registered_users_csv()
    click.echo("Administrator role granted. The existing password and account data were unchanged.")


@app.cli.command("export-registered-users")
@click.option(
    "--confirm-email",
    required=True,
    help="Confirm the designated BookBridge administrator account before exporting.",
)
def export_registered_users(confirm_email):
    """Write a password-free CSV to the private local database folder."""
    if confirm_email.strip().casefold() != INITIAL_ADMIN_EMAIL.casefold():
        raise click.ClickException("Only the designated BookBridge admin can export registered users.")
    administrator_password = click.prompt(
        "Designated administrator password", hide_input=True
    )
    database_path = Path(app.config["DATABASE"])
    export_directory = database_path.resolve().parent / "admin_exports"
    export_directory.mkdir(parents=True, exist_ok=True)
    output_path = export_directory / "registered_users.csv"
    temporary_path = export_directory / ".registered_users.csv.tmp"
    try:
        with sqlite3.connect(database_path, timeout=10) as db:
            admin = db.execute(
                """SELECT password_hash FROM users WHERE email = ? COLLATE NOCASE
                   AND is_admin = 1 AND is_active = 1""",
                (INITIAL_ADMIN_EMAIL,),
            ).fetchone()
            if not admin or not check_password_hash(
                admin[0], administrator_password
            ):
                raise click.ClickException(
                    "Administrator authentication failed."
                )
            users = db.execute(
                """SELECT id, name, email, created_at, is_admin, is_active
                   FROM users ORDER BY created_at, id"""
            ).fetchall()
        with temporary_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(
                ("User ID", "Full Name", "Email", "Registration Date", "Role", "Account Status")
            )
            writer.writerows(
                (
                    user[0], user[1], user[2], user[3],
                    "Admin" if user[4] else "Member",
                    "Active" if user[5] else "Suspended",
                )
                for user in users
            )
        temporary_path.replace(output_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    click.echo(f"Exported {len(users)} registered users to {output_path.resolve()}")


def clean_text(value, label, max_length, required=True):
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{label} is required.")
    if len(value) > max_length:
        raise ValueError(f"{label} must be {max_length} characters or fewer.")
    return value


def log_admin_action(admin_id, action, target_type, target_id, details=""):
    get_db().execute(
        """INSERT INTO admin_action_logs
           (admin_id, action, target_type, target_id, details, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (admin_id, action, target_type, target_id, details[:1000], utc_now()),
    )


def save_image_upload(upload):
    if not upload or not upload.filename:
        return None

    extension = Path(upload.filename).suffix.lower()
    expected_format = UPLOAD_EXTENSIONS.get(extension)
    if not expected_format:
        raise ValueError("Choose a JPG, JPEG, PNG, WEBP, GIF, or BMP image.")

    data = upload.stream.read(UPLOAD_MAX_BYTES + 1)
    if len(data) > UPLOAD_MAX_BYTES:
        raise ValueError("Each image must be 10 MB or smaller.")
    if not data:
        raise ValueError("The selected image is empty. Choose another file.")

    expected_image_format, expected_mime = expected_format
    submitted_mime = UPLOAD_MIME_ALIASES.get(upload.mimetype.lower(), upload.mimetype.lower())
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                actual_format = image.format
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                for frame in ImageSequence.Iterator(image):
                    frame.load()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning, OSError, SyntaxError,
            UnidentifiedImageError, EOFError, ValueError, OverflowError) as error:
        raise ValueError("That image is invalid or damaged. Choose a different image.") from error

    actual_mime = next(
        (mime for _extension, (image_format, mime) in UPLOAD_EXTENSIONS.items()
         if image_format == actual_format),
        None,
    )
    if actual_format != expected_image_format or actual_mime != expected_mime:
        raise ValueError("The image content does not match its file extension.")
    if submitted_mime and submitted_mime != actual_mime:
        raise ValueError("The image content type does not match the selected file.")

    upload_directory = Path(app.config["UPLOAD_FOLDER"])
    upload_directory.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}{extension}"
    with (upload_directory / filename).open("xb") as image_file:
        image_file.write(data)
    return filename


def remove_uploaded_image(filename):
    if filename:
        (Path(app.config["UPLOAD_FOLDER"]) / filename).unlink(missing_ok=True)


def current_user():
    if "current_user" not in g:
        user_id = session.get("user_id")
        user = None
        if user_id:
            user = get_db().execute(
                "SELECT id, name, email, is_admin, is_active FROM users WHERE id = ? AND is_active = 1",
                (user_id,),
            ).fetchone()
            if user is None:
                session.clear()
        g.current_user = user
    return g.current_user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user()["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def designated_admin_required(view):
    @wraps(view)
    @admin_required
    def wrapped(*args, **kwargs):
        if current_user()["email"].casefold() != INITIAL_ADMIN_EMAIL.casefold():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def password_is_strong(password):
    if not 8 <= len(password) <= 128:
        return False
    character_groups = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    return sum(character_groups) >= 3


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def unread_message_count(user_id):
    row = get_db().execute(
        """SELECT COUNT(*) AS total FROM messages
           WHERE recipient_id = ? AND read_at IS NULL AND is_hidden = 0""",
        (user_id,),
    ).fetchone()
    return row["total"]


@app.context_processor
def template_context():
    user = current_user()
    return {"current_user": user, "csrf_token": csrf_token, "categories": CATEGORIES,
            "current_year": datetime.now().year,
            "unread_message_count": unread_message_count(user["id"]) if user else 0}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not submitted or not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description="Your form session expired. Reload the page and try again.")


@app.route("/uploads/<filename>")
def uploaded_image(filename):
    if Path(filename).name != filename or Path(filename).suffix.lower() not in UPLOAD_EXTENSIONS:
        abort(404)

    db = get_db()
    public_image = db.execute(
        """SELECT 1 FROM books WHERE image_filename = ? AND is_active = 1
             AND moderation_status = 'approved'
           UNION ALL SELECT 1 FROM book_requests
             WHERE attachment_filename = ? AND is_active = 1
               AND moderation_status = 'approved' LIMIT 1""",
        (filename, filename),
    ).fetchone()
    if not public_image:
        private_image = db.execute(
            """SELECT enquiries.sender_id, books.owner_id
               FROM enquiries JOIN books ON books.id = enquiries.book_id
               WHERE enquiries.attachment_filename = ?
               UNION ALL
               SELECT books.owner_id, books.owner_id FROM books WHERE books.image_filename = ?
               UNION ALL
               SELECT book_requests.user_id, book_requests.user_id
               FROM book_requests WHERE book_requests.attachment_filename = ?""",
            (filename, filename, filename),
        ).fetchone()
        user = current_user()
        if (not private_image or not user
                or (user["id"] not in (private_image["sender_id"], private_image["owner_id"])
                    and not user["is_admin"])):
            abort(404)

    _image_format, image_mime = UPLOAD_EXTENSIONS[Path(filename).suffix.lower()]
    response = send_from_directory(
        app.config["UPLOAD_FOLDER"], filename, mimetype=image_mime, max_age=3600
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route("/")
def home():
    db = get_db()
    featured = db.execute(
        """SELECT books.*, users.name AS owner_name FROM books JOIN users ON users.id = books.owner_id
           WHERE books.is_active = 1 AND books.moderation_status = 'approved'
             AND users.is_active = 1 ORDER BY books.created_at DESC LIMIT 6"""
    ).fetchall()
    totals = db.execute(
        """SELECT category, COUNT(*) AS total FROM books
           WHERE is_active = 1 AND moderation_status = 'approved' GROUP BY category"""
    ).fetchall()
    return render_template(
        "home.html",
        featured=featured,
        category_counts={row["category"]: row["total"] for row in totals},
        conditions=CONDITIONS,
    )


@app.route("/books")
def browse():
    filters = {"q": request.args.get("q", "").strip()[:100], "category": request.args.get("category", ""),
               "condition": request.args.get("condition", ""), "location": request.args.get("location", "").strip()[:80],
               "type": request.args.get("type", "")}
    query = """SELECT books.*, users.name AS owner_name FROM books JOIN users ON users.id = books.owner_id
              WHERE books.is_active = 1 AND books.moderation_status = 'approved'
                AND users.is_active = 1"""
    values = []
    if filters["q"]:
        query += " AND (books.title LIKE ? OR books.author LIKE ? OR books.description LIKE ?)"
        term = f"%{filters['q']}%"
        values.extend([term, term, term])
    if filters["category"] in CATEGORIES:
        query += " AND books.category = ?"
        values.append(filters["category"])
    if filters["condition"] in CONDITIONS:
        query += " AND LOWER(books.condition) = LOWER(?)"
        values.append(filters["condition"])
    if filters["location"]:
        query += " AND books.location LIKE ?"
        values.append(f"%{filters['location']}%")
    if filters["type"] in LISTING_TYPES:
        query += " AND books.listing_type = ?"
        values.append(filters["type"])
    query += " ORDER BY books.created_at DESC LIMIT 100"
    books = get_db().execute(query, values).fetchall()
    return render_template("browse.html", books=books, filters=filters, conditions=CONDITIONS)


@app.route("/books/<int:book_id>")
def book_detail(book_id):
    db = get_db()
    book = db.execute(
        """SELECT books.*, users.name AS owner_name FROM books JOIN users ON users.id = books.owner_id
           WHERE books.id = ? AND books.is_active = 1
             AND books.moderation_status = 'approved' AND users.is_active = 1""", (book_id,)
    ).fetchone()
    if not book:
        abort(404)
    my_books = []
    if current_user():
        my_books = db.execute(
            "SELECT id, title FROM books WHERE owner_id = ? AND is_active = 1 AND listing_type = 'exchange' AND id != ? ORDER BY title",
            (current_user()["id"], book_id),
        ).fetchall()
    return render_template("book_detail.html", book=book, my_books=my_books)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user():
        return redirect(url_for("home"))
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        field_errors = {}
        if not name:
            field_errors["name"] = "Please enter your full name."
        elif len(name) > 80:
            field_errors["name"] = "Your full name must be 80 characters or fewer."
        if not email:
            field_errors["email"] = "Please enter your email address."
        elif len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            field_errors["email"] = "Please enter a valid email address."
        elif get_db().execute(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)
        ).fetchone():
            field_errors["email"] = "This email cannot be used for a new registration."
        if not password_is_strong(password):
            field_errors["password"] = "Please choose a stronger password."
        if password != confirmation:
            field_errors["confirm_password"] = "Passwords do not match."
        if field_errors:
            return render_template(
                "signup.html", field_errors=field_errors, form_name=name,
                form_email=email,
            )
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, generate_password_hash(password), utc_now()),
            )
            db.commit()
            sync_registered_users_csv()
            user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()
            flash("Your account is ready. Welcome to BookBridge!", "success")
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            db.rollback()
            return render_template(
                "signup.html",
                field_errors={"email": "This email cannot be used for a new registration."},
                form_name=name, form_email=email,
            )
    return render_template("signup.html", field_errors={}, form_name="", form_email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))
    field_errors = {}
    form_email = ""
    focus_field = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password", "")
        form_email = email
        if not email:
            field_errors["email"] = "Please enter your email address."
            focus_field = "email"
        elif len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            field_errors["email"] = "Please enter a valid email address."
            focus_field = "email"
        if not password:
            field_errors["password"] = "Please enter your password."
            focus_field = focus_field or "password"
        if field_errors:
            return render_template(
                "login.html", field_errors=field_errors, form_email=form_email,
                focus_field=focus_field,
            )

        user = get_db().execute(
            "SELECT id, password_hash, is_active FROM users WHERE email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()
            flash("You are now logged in.", "success")
            destination = request.args.get("next", "")
            if destination.startswith("/") and not destination.startswith("//"):
                return redirect(destination)
            return redirect(url_for("home"))
        if user and user["is_active"]:
            field_errors["password"] = "Incorrect password. Please try again."
            focus_field = "password"
        else:
            field_errors["email"] = "Invalid email or password."
            focus_field = "email"
    return render_template(
        "login.html", field_errors=field_errors, form_email=form_email,
        focus_field=focus_field,
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        session.pop("password_reset_id", None)
        session.pop("password_reset_grant", None)
        try:
            email = clean_text(request.form.get("email"), "Email", 254).lower()
            if "@" not in email or email.startswith("@") or email.endswith("@"):
                raise ValueError("Enter a valid email address.")
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("forgot_password"))

        if not _allow_password_reset_request(email, request.remote_addr):
            flash(PASSWORD_RESET_GENERIC_MESSAGE, "info")
            return redirect(url_for("forgot_password"))

        database = get_db()
        user = database.execute(
            "SELECT id FROM users WHERE email = ? COLLATE NOCASE AND is_active = 1",
            (email,),
        ).fetchone()
        if user:
            database.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
            otp = f"{secrets.randbelow(1_000_000):06d}"
            cursor = database.execute(
                "INSERT INTO password_reset_tokens (user_id, otp_hash, expires_at) VALUES (?, '', ?)",
                (user["id"], time.time() + PASSWORD_RESET_CODE_TTL),
            )
            reset_id = cursor.lastrowid
            database.execute(
                "UPDATE password_reset_tokens SET otp_hash = ? WHERE id = ?",
                (_password_reset_digest("otp", reset_id, otp), reset_id),
            )
            database.commit()
            try:
                send_password_reset_email(email, otp)
            except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
                database.execute("DELETE FROM password_reset_tokens WHERE id = ?", (reset_id,))
                database.commit()
                app.logger.error("Password reset email delivery failed.")

        flash(PASSWORD_RESET_GENERIC_MESSAGE, "info")
        return redirect(url_for("forgot_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password/verify", methods=["POST"])
def verify_password_reset_otp():
    session.pop("password_reset_id", None)
    session.pop("password_reset_grant", None)
    email = (request.form.get("email") or "").strip().lower()
    otp = request.form.get("otp", "")
    database = get_db()
    reset = database.execute(
        """SELECT reset.* FROM password_reset_tokens AS reset
           JOIN users ON users.id = reset.user_id
           WHERE users.email = ? COLLATE NOCASE AND users.is_active = 1""",
        (email,),
    ).fetchone() if len(email) <= 254 else None
    now = time.time()
    valid = False
    if reset:
        if reset["expires_at"] <= now or reset["attempts"] >= PASSWORD_RESET_MAX_ATTEMPTS:
            database.execute("DELETE FROM password_reset_tokens WHERE id = ?", (reset["id"],))
            database.commit()
        elif reset["otp_hash"] and re.fullmatch(r"\d{6}", otp):
            submitted_hash = _password_reset_digest("otp", reset["id"], otp)
            valid = hmac.compare_digest(reset["otp_hash"], submitted_hash)
            if not valid:
                attempts = reset["attempts"] + 1
                database.execute(
                    "UPDATE password_reset_tokens SET attempts = ?, otp_hash = ? WHERE id = ?",
                    (attempts, None if attempts >= PASSWORD_RESET_MAX_ATTEMPTS else reset["otp_hash"], reset["id"]),
                )
                database.commit()
        else:
            attempts = reset["attempts"] + 1
            database.execute(
                "UPDATE password_reset_tokens SET attempts = ?, otp_hash = ? WHERE id = ?",
                (attempts, None if attempts >= PASSWORD_RESET_MAX_ATTEMPTS else reset["otp_hash"], reset["id"]),
            )
            database.commit()

    if not valid:
        flash("The reset code is invalid or expired.", "error")
        return redirect(url_for("forgot_password"))

    grant = secrets.token_urlsafe(32)
    database.execute(
        """UPDATE password_reset_tokens
           SET otp_hash = NULL, verification_hash = ?, verification_expires_at = ?
           WHERE id = ?""",
        (_password_reset_digest("grant", reset["id"], grant), now + PASSWORD_RESET_GRANT_TTL, reset["id"]),
    )
    database.commit()
    session.clear()
    session["password_reset_id"] = reset["id"]
    session["password_reset_grant"] = grant
    csrf_token()
    flash("Code verified. Choose a new password.", "success")
    return redirect(url_for("reset_password"))


def _get_verified_password_reset():
    reset_id = session.get("password_reset_id")
    grant = session.get("password_reset_grant")
    if not isinstance(reset_id, int) or not isinstance(grant, str):
        return None
    reset = get_db().execute(
        """SELECT reset.* FROM password_reset_tokens AS reset
           JOIN users ON users.id = reset.user_id
           WHERE reset.id = ? AND users.is_active = 1""",
        (reset_id,),
    ).fetchone()
    if not reset:
        return None
    if not reset["verification_hash"] or not reset["verification_expires_at"] or reset["verification_expires_at"] <= time.time():
        get_db().execute("DELETE FROM password_reset_tokens WHERE id = ?", (reset_id,))
        get_db().commit()
        return None
    expected_hash = _password_reset_digest("grant", reset_id, grant)
    if not hmac.compare_digest(reset["verification_hash"], expected_hash):
        return None
    return reset


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    reset = _get_verified_password_reset()
    if not reset:
        session.pop("password_reset_id", None)
        session.pop("password_reset_grant", None)
        flash("Verify a valid reset code before choosing a new password.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        field_errors = {}
        if not password_is_strong(password):
            field_errors["password"] = "Please choose a stronger password."
        if password != confirmation:
            field_errors["confirm_password"] = "Passwords do not match."
        if field_errors:
            return render_template("reset_password.html", field_errors=field_errors)

        database = get_db()
        database.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(password), reset["user_id"]),
        )
        database.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (reset["user_id"],))
        database.commit()
        session.clear()
        flash("Your BookBridge password has been reset. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", field_errors={})


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    field_errors = {}
    if request.method == "POST":
        current_password_value = request.form.get("current_password", "")
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        stored = get_db().execute(
            "SELECT password_hash FROM users WHERE id = ?", (current_user()["id"],)
        ).fetchone()
        if not current_password_value:
            field_errors["current_password"] = "Please enter your current password."
        elif not check_password_hash(stored["password_hash"], current_password_value):
            field_errors["current_password"] = "Your current password is incorrect."
        if not password_is_strong(password):
            field_errors["password"] = "Please choose a stronger password."
        if password != confirmation:
            field_errors["confirm_password"] = "Passwords do not match."
        if not field_errors:
            get_db().execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), current_user()["id"]),
            )
            get_db().commit()
            flash("Your password has been updated.", "success")
            return redirect(url_for("profile"))
    return render_template("change_password.html", field_errors=field_errors)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


def save_book(listing_type):
    if listing_type not in LISTING_TYPES:
        abort(404)
    if request.method == "POST":
        try:
            title = clean_text(request.form.get("title"), "Title", 120)
            author = clean_text(request.form.get("author"), "Author", 100)
            category = clean_text(request.form.get("category"), "Category", 40)
            condition = clean_text(request.form.get("condition"), "Condition", 20)
            location = clean_text(request.form.get("location"), "Location", 100)
            description = clean_text(request.form.get("description"), "Description", 1000, False)
            if category not in CATEGORIES or condition not in CONDITIONS:
                raise ValueError("Choose a valid category and condition.")
            price = 0.0
            if listing_type == "sale":
                try:
                    price = float(request.form.get("price", ""))
                except ValueError as error:
                    raise ValueError("Enter a valid price in rupees.") from error
                if not 0 < price <= 100000:
                    raise ValueError("Price must be above ₹0 and no more than ₹100,000.")
            image_filename = save_image_upload(request.files.get("image"))
            db = get_db()
            try:
                db.execute(
                    """INSERT INTO books (
                           owner_id, title, author, category, description, condition, location,
                           price, listing_type, image_filename, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (current_user()["id"], title, author, category, description, condition,
                     location, price, listing_type, image_filename, utc_now()),
                )
                db.commit()
            except sqlite3.Error:
                remove_uploaded_image(image_filename)
                raise
            flash("Your book listing is now live.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template("list_book.html", listing_type=listing_type, conditions=CONDITIONS)


@app.route("/donate", methods=["GET", "POST"])
@login_required
def donate():
    return save_book("donation")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    return save_book("sale")


@app.route("/exchange/list", methods=["GET", "POST"])
@login_required
def list_exchange():
    return save_book("exchange")


@app.route("/requests", methods=["GET", "POST"])
def requests_page():
    if request.method == "POST":
        if not current_user():
            flash("Log in to post a book request.", "info")
            return redirect(url_for("login"))
        try:
            title = clean_text(request.form.get("title"), "Book title", 120)
            author = clean_text(request.form.get("author"), "Author", 100, False)
            category = clean_text(request.form.get("category"), "Category", 40)
            location = clean_text(request.form.get("location"), "Location", 100)
            message = clean_text(request.form.get("message"), "Details", 500, False)
            if category not in CATEGORIES:
                raise ValueError("Choose a valid category.")
            attachment_filename = save_image_upload(request.files.get("attachment"))
            db = get_db()
            try:
                db.execute(
                    """INSERT INTO book_requests (
                           user_id, title, author, category, location, message,
                           attachment_filename, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (current_user()["id"], title, author, category, location, message,
                     attachment_filename, utc_now()),
                )
                db.commit()
            except sqlite3.Error:
                remove_uploaded_image(attachment_filename)
                raise
            flash("Your request is visible to the community.", "success")
            return redirect(url_for("requests_page"))
        except ValueError as error:
            flash(str(error), "error")
    requests_list = get_db().execute(
        """SELECT book_requests.*, users.name AS user_name FROM book_requests JOIN users ON users.id = book_requests.user_id
           WHERE book_requests.is_active = 1 AND book_requests.moderation_status = 'approved'
             AND users.is_active = 1
           ORDER BY book_requests.created_at DESC LIMIT 100"""
    ).fetchall()
    return render_template("requests.html", requests_list=requests_list)


@app.route("/requests/<int:request_id>/toggle", methods=["POST"])
@login_required
def toggle_request(request_id):
    db = get_db()
    row = db.execute(
        "SELECT user_id, moderation_status FROM book_requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if not row or (row["user_id"] != current_user()["id"] and not current_user()["is_admin"]):
        abort(404)
    if row["moderation_status"] != "approved":
        abort(403)
    db.execute(
        """UPDATE book_requests SET is_active = 1 - is_active
           WHERE id = ? AND moderation_status = 'approved'""",
        (request_id,),
    )
    db.commit()
    flash("Request status updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/requests/<int:request_id>/edit", methods=["GET", "POST"])
@login_required
def edit_request(request_id):
    db = get_db()
    item = db.execute(
        """SELECT book_requests.*, users.name AS owner_name, users.email AS owner_email
           FROM book_requests JOIN users ON users.id = book_requests.user_id
           WHERE book_requests.id = ?""",
        (request_id,),
    ).fetchone()
    user = current_user()
    if not item or (item["user_id"] != user["id"] and not user["is_admin"]):
        abort(404)
    if item["moderation_status"] != "approved" and not user["is_admin"]:
        abort(403)
    if request.method == "POST":
        try:
            title = clean_text(request.form.get("title"), "Book title", 120)
            author = clean_text(request.form.get("author"), "Author", 100, False)
            category = clean_text(request.form.get("category"), "Category", 40)
            location = clean_text(request.form.get("location"), "Location", 100)
            message = clean_text(request.form.get("message"), "Details", 500, False)
            if category not in CATEGORIES:
                raise ValueError("Choose a valid category.")
            db.execute(
                """UPDATE book_requests SET title = ?, author = ?, category = ?,
                   location = ?, message = ? WHERE id = ?""",
                (title, author, category, location, message, request_id),
            )
            if user["is_admin"]:
                log_admin_action(
                    user["id"], "request_edited", "request", request_id
                )
            db.commit()
            flash("Book request updated.", "success")
            return redirect(url_for("admin_dashboard") if user["is_admin"] else url_for("dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template(
        "edit_request.html", item=item, categories=CATEGORIES,
        is_admin=bool(user["is_admin"]),
    )


@app.route("/requests/<int:request_id>/delete", methods=["POST"])
@login_required
def delete_own_request(request_id):
    db = get_db()
    user = current_user()
    result = db.execute(
        """UPDATE book_requests SET is_active = 0, moderation_status = 'deleted'
           WHERE id = ? AND moderation_status = 'approved'
             AND (user_id = ? OR ? = 1)""",
        (request_id, user["id"], user["is_admin"]),
    )
    if result.rowcount != 1:
        abort(404)
    if user["is_admin"]:
        log_admin_action(user["id"], "request_deleted", "request", request_id)
    db.commit()
    flash("Book request removed.", "success")
    return redirect(url_for("admin_dashboard") if user["is_admin"] else url_for("dashboard"))


@app.route("/books/<int:book_id>/toggle", methods=["POST"])
@login_required
def toggle_book(book_id):
    db = get_db()
    row = db.execute(
        "SELECT owner_id, moderation_status FROM books WHERE id = ?", (book_id,)
    ).fetchone()
    if not row or (row["owner_id"] != current_user()["id"] and not current_user()["is_admin"]):
        abort(404)
    if row["moderation_status"] != "approved":
        abort(403)
    db.execute(
        "UPDATE books SET is_active = 1 - is_active WHERE id = ? AND moderation_status = 'approved'",
        (book_id,),
    )
    db.commit()
    flash("Listing status updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/books/<int:book_id>/edit", methods=["GET", "POST"])
@login_required
def edit_own_book(book_id):
    db = get_db()
    book = db.execute(
        """SELECT books.*, users.name AS owner_name, users.email AS owner_email
           FROM books JOIN users ON users.id = books.owner_id WHERE books.id = ?""",
        (book_id,),
    ).fetchone()
    if not book or book["owner_id"] != current_user()["id"]:
        abort(404)
    if book["moderation_status"] != "approved":
        abort(403)
    if request.method == "POST":
        try:
            title = clean_text(request.form.get("title"), "Title", 120)
            author = clean_text(request.form.get("author"), "Author", 100)
            category = clean_text(request.form.get("category"), "Category", 40)
            condition = clean_text(request.form.get("condition"), "Condition", 20)
            location = clean_text(request.form.get("location"), "Location", 100)
            description = clean_text(request.form.get("description"), "Description", 1000, False)
            if category not in CATEGORIES or condition not in CONDITIONS:
                raise ValueError("Choose a valid category and condition.")
            price = book["price"]
            if book["listing_type"] == "sale":
                try:
                    price = float(request.form.get("price", ""))
                except ValueError as error:
                    raise ValueError("Enter a valid price in rupees.") from error
                if not 0 < price <= 100000:
                    raise ValueError("Price must be above ₹0 and no more than ₹100,000.")
            db.execute(
                """UPDATE books SET title = ?, author = ?, category = ?, condition = ?,
                   location = ?, description = ?, price = ? WHERE id = ? AND owner_id = ?""",
                (title, author, category, condition, location, description, price,
                 book_id, current_user()["id"]),
            )
            db.commit()
            flash("Your listing was updated.", "success")
            return redirect(url_for("dashboard"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template(
        "admin_edit_book.html", book=book, conditions=CONDITIONS, categories=CATEGORIES,
        page_heading="Edit your book listing", is_admin=False,
    )


@app.route("/books/<int:book_id>/delete", methods=["POST"])
@login_required
def delete_own_book(book_id):
    db = get_db()
    result = db.execute(
        """UPDATE books SET is_active = 0, moderation_status = 'deleted'
           WHERE id = ? AND owner_id = ? AND moderation_status = 'approved'""",
        (book_id, current_user()["id"]),
    )
    if result.rowcount != 1:
        abort(404)
    db.commit()
    flash("Your listing was removed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/exchange/offers", methods=["POST"])
@login_required
def make_exchange_offer():
    try:
        book_id = int(request.form.get("book_id", ""))
        offered_book_id = int(request.form.get("offered_book_id", ""))
        message = clean_text(request.form.get("message"), "Message", 500, False)
    except (TypeError, ValueError):
        flash("Choose a book to offer and try again.", "error")
        return redirect(url_for("browse"))
    db = get_db()
    target = db.execute("SELECT id, owner_id, listing_type FROM books WHERE id = ? AND is_active = 1", (book_id,)).fetchone()
    offered = db.execute("SELECT id, owner_id, listing_type FROM books WHERE id = ? AND is_active = 1", (offered_book_id,)).fetchone()
    if (not target or target["listing_type"] != "exchange" or target["owner_id"] == current_user()["id"]
            or not offered or offered["owner_id"] != current_user()["id"] or offered["listing_type"] != "exchange"):
        flash("That exchange offer is not valid.", "error")
    else:
        duplicate = db.execute("SELECT 1 FROM exchange_offers WHERE book_id = ? AND offered_book_id = ? AND user_id = ? AND status = 'pending'",
                               (book_id, offered_book_id, current_user()["id"])).fetchone()
        if duplicate:
            flash("You already have a pending offer for this book.", "info")
        else:
            db.execute("INSERT INTO exchange_offers (book_id, offered_book_id, user_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
                       (book_id, offered_book_id, current_user()["id"], message, utc_now()))
            db.commit()
            flash("Your exchange offer was sent.", "success")
    return redirect(url_for("book_detail", book_id=book_id))


@app.route("/exchange/offers/<int:offer_id>/<decision>", methods=["POST"])
@login_required
def decide_exchange(offer_id, decision):
    if decision not in {"accept", "reject"}:
        abort(404)
    db = get_db()
    offer = db.execute("""SELECT exchange_offers.*, books.owner_id AS book_owner FROM exchange_offers
                          JOIN books ON books.id = exchange_offers.book_id WHERE exchange_offers.id = ?""", (offer_id,)).fetchone()
    if not offer or offer["book_owner"] != current_user()["id"]:
        abort(404)
    if offer["status"] != "pending":
        flash("This offer has already been decided.", "info")
    else:
        status = "accepted" if decision == "accept" else "rejected"
        db.execute("UPDATE exchange_offers SET status = ? WHERE id = ? AND status = 'pending'", (status, offer_id))
        if status == "accepted":
            db.execute("UPDATE exchange_offers SET status = 'rejected' WHERE book_id = ? AND id != ? AND status = 'pending'",
                       (offer["book_id"], offer_id))
        db.commit()
        flash(f"Offer {status}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/enquiries", methods=["POST"])
@login_required
def send_enquiry():
    try:
        book_id = int(request.form.get("book_id", ""))
        message = clean_text(request.form.get("message"), "Message", 1000)
    except (TypeError, ValueError):
        flash("Enter a message to send your enquiry.", "error")
        return redirect(url_for("browse"))
    db = get_db()
    book = db.execute("SELECT id, owner_id FROM books WHERE id = ? AND is_active = 1", (book_id,)).fetchone()
    if not book or book["owner_id"] == current_user()["id"]:
        abort(404)
    try:
        attachment_filename = save_image_upload(request.files.get("attachment"))
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("book_detail", book_id=book_id))
    try:
        db.execute(
            """INSERT INTO enquiries (
                   book_id, sender_id, recipient_id, message, attachment_filename, created_at
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (book_id, current_user()["id"], book["owner_id"], message, attachment_filename, utc_now()),
        )
        db.commit()
    except sqlite3.Error:
        remove_uploaded_image(attachment_filename)
        raise
    flash("Your enquiry was sent to the book owner.", "success")
    return redirect(url_for("book_detail", book_id=book_id))


def get_enquiry_for_participant(enquiry_id, user_id):
    return get_db().execute(
        """SELECT enquiries.*, books.title AS book_title, books.owner_id,
                  buyer.name AS buyer_name, owner.name AS owner_name
           FROM enquiries
           JOIN books ON books.id = enquiries.book_id
           JOIN users AS buyer ON buyer.id = enquiries.sender_id
           JOIN users AS owner ON owner.id = books.owner_id
           WHERE enquiries.id = ? AND enquiries.recipient_id = books.owner_id
             AND (enquiries.sender_id = ? OR books.owner_id = ?)""",
        (enquiry_id, user_id, user_id),
    ).fetchone()


@app.route("/messages")
@login_required
def messages():
    user_id = current_user()["id"]
    conversations = get_db().execute(
        """SELECT enquiries.id AS enquiry_id, enquiries.message AS enquiry_message,
                  enquiries.created_at AS enquiry_created_at, books.id AS book_id,
                  books.title AS book_title, books.owner_id,
                  buyer.name AS buyer_name, owner.name AS owner_name,
                  COALESCE(
                      (SELECT messages.body FROM messages
                       WHERE messages.enquiry_id = enquiries.id AND messages.is_hidden = 0
                       ORDER BY messages.id DESC LIMIT 1),
                      enquiries.message
                  ) AS latest_message,
                  COALESCE(
                      (SELECT messages.created_at FROM messages
                       WHERE messages.enquiry_id = enquiries.id AND messages.is_hidden = 0
                       ORDER BY messages.id DESC LIMIT 1),
                      enquiries.created_at
                  ) AS latest_at,
                  (SELECT COUNT(*) FROM messages
                   WHERE messages.enquiry_id = enquiries.id
                     AND messages.recipient_id = ? AND messages.read_at IS NULL
                     AND messages.is_hidden = 0) AS unread_count
           FROM enquiries
           JOIN books ON books.id = enquiries.book_id
           JOIN users AS buyer ON buyer.id = enquiries.sender_id
           JOIN users AS owner ON owner.id = books.owner_id
           WHERE enquiries.recipient_id = books.owner_id
             AND (enquiries.sender_id = ? OR books.owner_id = ?)
           ORDER BY latest_at DESC, enquiries.id DESC""",
        (user_id, user_id, user_id),
    ).fetchall()
    return render_template("messages.html", conversations=conversations)


@app.route("/messages/<int:enquiry_id>", methods=["GET", "POST"])
@login_required
def conversation(enquiry_id):
    user_id = current_user()["id"]
    enquiry = get_enquiry_for_participant(enquiry_id, user_id)
    if not enquiry:
        abort(404)

    if request.method == "POST":
        try:
            body = clean_text(request.form.get("body"), "Message", 2000)
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("conversation", enquiry_id=enquiry_id))
        recipient_id = enquiry["owner_id"] if user_id == enquiry["sender_id"] else enquiry["sender_id"]
        db = get_db()
        db.execute(
            """INSERT INTO messages (enquiry_id, sender_id, recipient_id, body, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (enquiry_id, user_id, recipient_id, body, utc_now()),
        )
        db.commit()
        return redirect(url_for("conversation", enquiry_id=enquiry_id))

    db = get_db()
    db.execute(
        """UPDATE messages SET read_at = ?
           WHERE enquiry_id = ? AND recipient_id = ? AND read_at IS NULL AND is_hidden = 0""",
        (utc_now(), enquiry_id, user_id),
    )
    db.commit()
    conversation_messages = db.execute(
        """SELECT messages.*, users.name AS sender_name
           FROM messages JOIN users ON users.id = messages.sender_id
           WHERE messages.enquiry_id = ? AND messages.is_hidden = 0
           ORDER BY messages.id""",
        (enquiry_id,),
    ).fetchall()
    other_participant = (
        enquiry["owner_name"] if user_id == enquiry["sender_id"] else enquiry["buyer_name"]
    )
    return render_template(
        "conversation.html",
        enquiry=enquiry,
        messages=conversation_messages,
        other_participant=other_participant,
    )


@app.route("/messages/<int:enquiry_id>/report/<int:message_id>", methods=["POST"])
@login_required
def report_message(enquiry_id, message_id):
    user_id = current_user()["id"]
    enquiry = get_enquiry_for_participant(enquiry_id, user_id)
    if not enquiry:
        abort(404)
    db = get_db()
    message = db.execute(
        "SELECT id, sender_id FROM messages WHERE id = ? AND enquiry_id = ?",
        (message_id, enquiry_id),
    ).fetchone()
    if not message or message["sender_id"] == user_id:
        abort(404)
    try:
        reason = clean_text(request.form.get("reason"), "Report reason", 1000)
        db.execute(
            """INSERT INTO message_reports
               (message_id, reporter_id, reason, created_at)
               VALUES (?, ?, ?, ?)""",
            (message_id, user_id, reason, utc_now()),
        )
        db.commit()
        flash("The message was reported to BookBridge support.", "success")
    except ValueError as error:
        flash(str(error), "error")
    except sqlite3.IntegrityError:
        db.rollback()
        flash("You have already reported this message.", "info")
    return redirect(url_for("conversation", enquiry_id=enquiry_id))


@app.route("/admin/message-reports", methods=["GET", "POST"])
@admin_required
def admin_message_reports():
    db = get_db()
    if request.method == "POST":
        try:
            report_id = int(request.form.get("report_id", ""))
        except ValueError:
            abort(400)
        action = request.form.get("action", "")
        if action not in {"review", "remove"}:
            abort(400)
        report = db.execute(
            "SELECT id, message_id, status FROM message_reports WHERE id = ?",
            (report_id,),
        ).fetchone()
        if not report:
            abort(404)
        if action == "remove":
            db.execute("UPDATE messages SET is_hidden = 1 WHERE id = ?", (report["message_id"],))
            db.execute(
                "UPDATE message_reports SET status = 'Removed' WHERE message_id = ?",
                (report["message_id"],),
            )
        elif report["status"] == "Open":
            db.execute(
                "UPDATE message_reports SET status = 'Reviewed' WHERE id = ?",
                (report_id,),
            )
        log_admin_action(
            current_user()["id"],
            "message_removed" if action == "remove" else "message_report_reviewed",
            "message",
            report["message_id"],
            f"Report #{report_id}",
        )
        db.commit()
        flash("Reported message moderation was saved.", "success")
        return redirect(url_for("admin_message_reports"))

    status = request.args.get("status", "")
    if status not in {"Open", "Reviewed", "Removed"}:
        status = ""
    reports = db.execute(
        """SELECT message_reports.*, messages.body, messages.is_hidden,
                  sender.name AS sender_name, reporter.name AS reporter_name,
                  enquiries.id AS enquiry_id, books.title AS book_title
           FROM message_reports
           JOIN messages ON messages.id = message_reports.message_id
           JOIN users AS sender ON sender.id = messages.sender_id
           JOIN users AS reporter ON reporter.id = message_reports.reporter_id
           JOIN enquiries ON enquiries.id = messages.enquiry_id
           JOIN books ON books.id = enquiries.book_id
           WHERE (? = '' OR message_reports.status = ?)
           ORDER BY CASE message_reports.status
                      WHEN 'Open' THEN 0 WHEN 'Reviewed' THEN 1 ELSE 2
                    END, message_reports.created_at DESC""",
        (status, status),
    ).fetchall()
    return render_template("admin_message_reports.html", reports=reports, selected_status=status)


@app.route("/low-cost")
def low_cost():
    maximum = request.args.get("max", "200")
    if maximum not in {"50", "100", "200"}:
        maximum = "200"
    books = get_db().execute(
        """SELECT books.*, users.name AS owner_name FROM books JOIN users ON users.id = books.owner_id
           WHERE books.is_active = 1 AND books.moderation_status = 'approved'
             AND books.listing_type = 'sale' AND books.price <= ? AND users.is_active = 1
           ORDER BY books.price ASC, books.created_at DESC LIMIT 100""", (float(maximum),)
    ).fetchall()
    return render_template("low_cost.html", books=books, maximum=maximum)


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = current_user()["id"]
    listing_filter = request.args.get("type", "")
    if listing_filter not in LISTING_TYPES and not current_user()["is_admin"]:
        listing_filter = ""
    elif listing_filter not in LISTING_TYPES and listing_filter != "all":
        listing_filter = ""
    listings = db.execute(
        """SELECT * FROM books WHERE owner_id = ? AND (? = '' OR listing_type = ?)
           ORDER BY created_at DESC""",
        (user_id, "" if listing_filter == "all" else listing_filter,
         "" if listing_filter == "all" else listing_filter),
    ).fetchall()
    listing_totals = {
        row["listing_type"]: row["total"]
        for row in db.execute(
            """SELECT listing_type, COUNT(*) AS total FROM books
               WHERE owner_id = ? GROUP BY listing_type""",
            (user_id,),
        ).fetchall()
    }
    my_requests = db.execute("SELECT * FROM book_requests WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    offers_received = db.execute(
        """SELECT exchange_offers.*, books.title AS target_title, offered.title AS offered_title, users.name AS sender_name
           FROM exchange_offers JOIN books ON books.id = exchange_offers.book_id
           JOIN books AS offered ON offered.id = exchange_offers.offered_book_id JOIN users ON users.id = exchange_offers.user_id
           WHERE books.owner_id = ? ORDER BY exchange_offers.created_at DESC""", (user_id,)
    ).fetchall()
    offers_sent = db.execute(
        """SELECT exchange_offers.*, books.title AS target_title, offered.title AS offered_title FROM exchange_offers
           JOIN books ON books.id = exchange_offers.book_id JOIN books AS offered ON offered.id = exchange_offers.offered_book_id
           WHERE exchange_offers.user_id = ? ORDER BY exchange_offers.created_at DESC""", (user_id,)
    ).fetchall()
    enquiries = db.execute(
        """SELECT enquiries.*, books.title AS book_title, sender.name AS sender_name,
                  recipient.name AS recipient_name,
                  (SELECT COUNT(*) FROM messages
                   WHERE messages.enquiry_id = enquiries.id
                     AND messages.recipient_id = ? AND messages.read_at IS NULL) AS unread_count
           FROM enquiries JOIN books ON books.id = enquiries.book_id JOIN users AS sender ON sender.id = enquiries.sender_id
           JOIN users AS recipient ON recipient.id = enquiries.recipient_id
           WHERE enquiries.sender_id = ? OR enquiries.recipient_id = ? ORDER BY enquiries.created_at DESC""",
        (user_id, user_id, user_id),
    ).fetchall()
    tickets = db.execute(
        """SELECT id, subject, status, updated_at FROM support_tickets
           WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5""",
        (user_id,),
    ).fetchall()
    admin_stats = {}
    recent_admin_actions = []
    admin_dashboard_tickets = []
    if current_user()["is_admin"]:
        admin_stats = {
            "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "books": db.execute("SELECT COUNT(*) FROM books").fetchone()[0],
            "donations": db.execute(
                "SELECT COUNT(*) FROM books WHERE listing_type = 'donation'"
            ).fetchone()[0],
            "exchanges": db.execute(
                "SELECT COUNT(*) FROM books WHERE listing_type = 'exchange'"
            ).fetchone()[0],
            "sales": db.execute(
                "SELECT COUNT(*) FROM books WHERE listing_type = 'sale'"
            ).fetchone()[0],
            "requests": db.execute("SELECT COUNT(*) FROM book_requests").fetchone()[0],
            "open_tickets": db.execute(
                "SELECT COUNT(*) FROM support_tickets WHERE status = 'Open'"
            ).fetchone()[0],
            "resolved_tickets": db.execute(
                "SELECT COUNT(*) FROM support_tickets WHERE status = 'Resolved'"
            ).fetchone()[0],
            "reports": db.execute(
                "SELECT COUNT(*) FROM message_reports WHERE status = 'Open'"
            ).fetchone()[0],
        }
        recent_admin_actions = db.execute(
            """SELECT admin_action_logs.*, users.name AS admin_name
               FROM admin_action_logs JOIN users ON users.id = admin_action_logs.admin_id
               ORDER BY admin_action_logs.id DESC LIMIT 8"""
        ).fetchall()
        admin_dashboard_tickets = db.execute(
            """SELECT id, subject, status, updated_at FROM support_tickets
               ORDER BY CASE status WHEN 'Open' THEN 0 WHEN 'In Progress' THEN 1
                 WHEN 'Resolved' THEN 2 ELSE 3 END, updated_at DESC LIMIT 5"""
        ).fetchall()
    return render_template("dashboard.html", listings=listings, my_requests=my_requests,
                           offers_received=offers_received, offers_sent=offers_sent, enquiries=enquiries,
                           listing_totals=listing_totals, listing_filter=listing_filter,
                           admin_stats=admin_stats, recent_admin_actions=recent_admin_actions,
                           admin_dashboard_tickets=admin_dashboard_tickets,
                           is_designated_admin=(
                               current_user()["email"].casefold()
                               == INITIAL_ADMIN_EMAIL.casefold()
                           ),
                           tickets=tickets, pending_exchange_count=sum(
                               offer["status"] == "pending" for offer in offers_received
                           ), ticket_total=db.execute(
                               "SELECT COUNT(*) FROM support_tickets WHERE user_id = ?",
                               (user_id,),
                           ).fetchone()[0])


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/help")
def help_center():
    admin_tickets = []
    selected_status = request.args.get("status", "")
    ticket_query = request.args.get("q", "").strip()[:100]
    if selected_status not in SUPPORT_STATUSES:
        selected_status = ""
    if current_user() and current_user()["is_admin"]:
        admin_tickets = get_db().execute(
            """SELECT support_tickets.id, support_tickets.name, support_tickets.email,
                      support_tickets.subject, support_tickets.status,
                      support_tickets.updated_at, books.title AS book_title
               FROM support_tickets
               LEFT JOIN books ON books.id = support_tickets.book_id
               WHERE (? = '' OR support_tickets.status = ?)
                 AND (? = '' OR support_tickets.subject LIKE ?
                   OR support_tickets.name LIKE ? OR support_tickets.email LIKE ?
                   OR support_tickets.description LIKE ?)
               ORDER BY CASE support_tickets.status
                          WHEN 'Open' THEN 0 WHEN 'In Progress' THEN 1
                          WHEN 'Resolved' THEN 2 ELSE 3
                        END, support_tickets.updated_at DESC""",
            (
                selected_status, selected_status, ticket_query,
                f"%{ticket_query}%", f"%{ticket_query}%",
                f"%{ticket_query}%", f"%{ticket_query}%",
            ),
        ).fetchall()
    return render_template(
        "help.html", admin_tickets=admin_tickets,
        selected_status=selected_status, ticket_query=ticket_query,
    )


@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    db = get_db()
    if request.method == "POST":
        try:
            category = clean_text(request.form.get("category"), "Issue category", 40)
            subject = clean_text(request.form.get("subject"), "Subject", 120)
            description = clean_text(request.form.get("description"), "Description", 5000)
            if category not in SUPPORT_CATEGORIES:
                raise ValueError("Choose a valid issue category.")

            book_id_value = (request.form.get("book_id") or "").strip()
            book_id = None
            if book_id_value:
                try:
                    book_id = int(book_id_value)
                except ValueError as error:
                    raise ValueError("Choose a valid related listing, or leave it blank.") from error
                related_book = db.execute(
                    """SELECT id FROM books WHERE id = ? AND is_active = 1
                       AND moderation_status = 'approved'""",
                    (book_id,),
                ).fetchone()
                if not related_book:
                    raise ValueError("Choose an active listing, or leave it blank.")

            now = utc_now()
            cursor = db.execute(
                """INSERT INTO support_tickets (
                       user_id, name, email, category, subject, description, book_id,
                       status, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)""",
                (current_user()["id"], current_user()["name"], current_user()["email"],
                 category, subject, description, book_id, now, now),
            )
            db.commit()
            ticket_id = cursor.lastrowid
            flash("Your private support ticket was submitted.", "success")
            return redirect(url_for("support_ticket", ticket_id=ticket_id))
        except ValueError as error:
            flash(str(error), "error")

    books = db.execute(
        """SELECT id, title FROM books WHERE is_active = 1
           AND moderation_status = 'approved' ORDER BY title LIMIT 200"""
    ).fetchall()
    return render_template(
        "support_form.html",
        support_categories=SUPPORT_CATEGORIES,
        books=books,
    )


@app.route("/support/tickets")
@login_required
def support_tickets():
    tickets = get_db().execute(
        """SELECT support_tickets.*, books.title AS book_title
           FROM support_tickets
           LEFT JOIN books ON books.id = support_tickets.book_id
           WHERE support_tickets.user_id = ?
           ORDER BY support_tickets.updated_at DESC, support_tickets.id DESC""",
        (current_user()["id"],),
    ).fetchall()
    return render_template("support_tickets.html", tickets=tickets)


@app.route("/support/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def support_ticket(ticket_id):
    db = get_db()
    user = current_user()
    ticket = db.execute(
        """SELECT support_tickets.*, books.title AS book_title
           FROM support_tickets
           LEFT JOIN books ON books.id = support_tickets.book_id
           WHERE support_tickets.id = ?""",
        (ticket_id,),
    ).fetchone()
    if not ticket or (not user["is_admin"] and ticket["user_id"] != user["id"]):
        abort(404)

    if request.method == "POST":
        try:
            body = clean_text(request.form.get("body"), "Reply", 5000, False)
            internal_note = ""
            if user["is_admin"]:
                status = clean_text(request.form.get("status"), "Ticket status", 20)
                if status not in SUPPORT_STATUSES:
                    raise ValueError("Choose a valid ticket status.")
                internal_note = clean_text(
                    request.form.get("internal_note"), "Internal note", 5000, False
                )
                if not body and not internal_note and status == ticket["status"]:
                    raise ValueError("Write a reply or internal note, or change the ticket status.")
            else:
                if ticket["status"] == "Closed":
                    raise ValueError("This ticket is closed. Contact support again to start a new ticket.")
                status = ticket["status"]
                if not body:
                    raise ValueError("Reply is required.")

            now = utc_now()
            if body:
                db.execute(
                    """INSERT INTO support_ticket_messages (ticket_id, sender_id, body, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (ticket_id, user["id"], body, now),
                )
            if internal_note:
                db.execute(
                    """INSERT INTO support_ticket_internal_notes
                       (ticket_id, admin_id, body, created_at) VALUES (?, ?, ?, ?)""",
                    (ticket_id, user["id"], internal_note, now),
                )
            db.execute(
                "UPDATE support_tickets SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, ticket_id),
            )
            if user["is_admin"]:
                log_admin_action(
                    user["id"], "support_ticket_updated", "support_ticket", ticket_id,
                    f"status={status}",
                )
            db.commit()
            flash("Your ticket update was saved.", "success")
            return redirect(url_for("support_ticket", ticket_id=ticket_id))
        except ValueError as error:
            flash(str(error), "error")

    replies = db.execute(
        """SELECT support_ticket_messages.*, users.name AS sender_name, users.is_admin AS sender_is_admin
           FROM support_ticket_messages
           JOIN users ON users.id = support_ticket_messages.sender_id
           WHERE support_ticket_messages.ticket_id = ?
           ORDER BY support_ticket_messages.id""",
        (ticket_id,),
    ).fetchall()
    internal_notes = []
    if user["is_admin"]:
        internal_notes = db.execute(
            """SELECT support_ticket_internal_notes.*, users.name AS admin_name
               FROM support_ticket_internal_notes
               JOIN users ON users.id = support_ticket_internal_notes.admin_id
               WHERE support_ticket_internal_notes.ticket_id = ?
               ORDER BY support_ticket_internal_notes.id""",
            (ticket_id,),
        ).fetchall()
    return render_template(
        "support_ticket.html",
        ticket=ticket,
        replies=replies,
        internal_notes=internal_notes,
        support_statuses=SUPPORT_STATUSES,
    )


@app.route("/admin/support-tickets")
@admin_required
def admin_support_tickets():
    status = request.args.get("status", "")
    if status not in SUPPORT_STATUSES:
        status = ""
    query = request.args.get("q", "").strip()[:100]
    tickets = get_db().execute(
        """SELECT support_tickets.*, books.title AS book_title
           FROM support_tickets
           LEFT JOIN books ON books.id = support_tickets.book_id
           WHERE (? = '' OR support_tickets.status = ?)
             AND (? = '' OR support_tickets.subject LIKE ?
               OR support_tickets.name LIKE ? OR support_tickets.email LIKE ?
               OR support_tickets.description LIKE ?)
           ORDER BY CASE support_tickets.status
                        WHEN 'Open' THEN 0 WHEN 'In Progress' THEN 1
                        WHEN 'Resolved' THEN 2 ELSE 3
                    END,
                    support_tickets.updated_at DESC, support_tickets.id DESC"""
        , (status, status, query, f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%")
    ).fetchall()
    return render_template(
        "admin_support_tickets.html", tickets=tickets,
        selected_status=status, ticket_query=query,
    )


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        try:
            name = clean_text(request.form.get("name"), "Name", 80)
            email = clean_text(request.form.get("email"), "Email", 254).lower()
            subject = clean_text(request.form.get("subject"), "Subject", 120)
            message = clean_text(request.form.get("message"), "Message", 2000)
            if "@" not in email:
                raise ValueError("Enter a valid email address.")
            user = current_user()
            db = get_db()
            db.execute("INSERT INTO feedback (user_id, name, email, subject, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                       (user["id"] if user else None, name, email, subject, message, utc_now()))
            db.commit()
            flash("Thanks for your feedback. It has been recorded.", "success")
            return redirect(url_for("contact"))
        except ValueError as error:
            flash(str(error), "error")
    return render_template("contact.html")


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        try:
            record_id = int(request.form.get("record_id", ""))
        except ValueError:
            abort(400)
        if action == "toggle_book":
            result = db.execute(
                """UPDATE books SET is_active = 1 - is_active
                   WHERE id = ? AND moderation_status = 'approved'""",
                (record_id,),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(current_user()["id"], "visibility_toggled", "book", record_id)
        elif action == "set_book_status":
            status = request.form.get("status", "")
            if status not in {"approved", "rejected"}:
                abort(400)
            result = db.execute(
                """UPDATE books SET moderation_status = ?, is_active = ?
                   WHERE id = ?""",
                (status, int(status == "approved"), record_id),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(
                current_user()["id"], f"listing_{status}", "book", record_id
            )
        elif action == "delete_book":
            result = db.execute(
                "UPDATE books SET is_active = 0, moderation_status = 'deleted' WHERE id = ?",
                (record_id,),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(current_user()["id"], "listing_deleted", "book", record_id)
        elif action == "toggle_request":
            result = db.execute(
                """UPDATE book_requests SET is_active = 1 - is_active
                   WHERE id = ? AND moderation_status = 'approved'""",
                (record_id,),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(current_user()["id"], "request_visibility_toggled", "request", record_id)
        elif action == "set_request_status":
            status = request.form.get("status", "")
            if status not in {"approved", "rejected"}:
                abort(400)
            result = db.execute(
                """UPDATE book_requests SET moderation_status = ?, is_active = ?
                   WHERE id = ?""",
                (status, int(status == "approved"), record_id),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(
                current_user()["id"], f"request_{status}", "request", record_id
            )
        elif action == "delete_request":
            result = db.execute(
                """UPDATE book_requests SET is_active = 0, moderation_status = 'deleted'
                   WHERE id = ?""",
                (record_id,),
            )
            if result.rowcount != 1:
                abort(404)
            log_admin_action(current_user()["id"], "request_deleted", "request", record_id)
        else:
            abort(400)
        db.commit()
        flash("Admin change saved.", "success")
        return redirect(url_for("admin_dashboard"))
    book_query = request.args.get("q", "").strip()[:100]
    listing_type = request.args.get("type", "")
    moderation_status = request.args.get("status", "")
    category_filter = request.args.get("category", "")
    if category_filter not in CATEGORIES:
        category_filter = ""
    owner_filter = request.args.get("owner", "").strip()[:100]
    request_status_filter = request.args.get("request_status", "")
    request_category_filter = request.args.get("request_category", "")
    if request_category_filter not in CATEGORIES:
        request_category_filter = ""
    request_owner_filter = request.args.get("request_owner", "").strip()[:100]
    book_sql = """SELECT books.*, users.name AS owner_name, users.email AS owner_email
                  FROM books JOIN users ON users.id = books.owner_id WHERE 1 = 1"""
    book_values = []
    if book_query:
        book_sql += " AND (books.title LIKE ? OR books.author LIKE ? OR users.name LIKE ? OR users.email LIKE ?)"
        term = f"%{book_query}%"
        book_values.extend((term, term, term, term))
    if listing_type in LISTING_TYPES:
        book_sql += " AND books.listing_type = ?"
        book_values.append(listing_type)
    if moderation_status in {"approved", "rejected", "deleted"}:
        book_sql += " AND books.moderation_status = ?"
        book_values.append(moderation_status)
    if category_filter in CATEGORIES:
        book_sql += " AND books.category = ?"
        book_values.append(category_filter)
    if owner_filter:
        book_sql += " AND (users.name LIKE ? OR users.email LIKE ?)"
        book_values.extend((f"%{owner_filter}%", f"%{owner_filter}%"))
    book_sql += " ORDER BY books.created_at DESC"
    books = db.execute(book_sql, book_values).fetchall()
    if request_status_filter not in {"approved", "rejected", "deleted"}:
        request_status_filter = ""
    request_query = request.args.get("request_q", "").strip()[:100]
    request_sql = """SELECT book_requests.*, users.name AS owner_name, users.email AS owner_email
                     FROM book_requests JOIN users ON users.id = book_requests.user_id
                     WHERE (? = '' OR book_requests.moderation_status = ?)
                       AND (? = '' OR book_requests.title LIKE ? OR book_requests.author LIKE ?
                         OR users.name LIKE ? OR users.email LIKE ? OR book_requests.message LIKE ?)"""
    request_values = [
        request_status_filter, request_status_filter, request_query,
        f"%{request_query}%", f"%{request_query}%", f"%{request_query}%",
        f"%{request_query}%", f"%{request_query}%",
    ]
    if request_category_filter:
        request_sql += " AND book_requests.category = ?"
        request_values.append(request_category_filter)
    if request_owner_filter:
        request_sql += " AND (users.name LIKE ? OR users.email LIKE ?)"
        request_values.extend((f"%{request_owner_filter}%", f"%{request_owner_filter}%"))
    request_sql += " ORDER BY book_requests.created_at DESC"
    book_requests = db.execute(
        request_sql, request_values
    ).fetchall()
    feedback_items = db.execute("SELECT * FROM feedback ORDER BY created_at DESC").fetchall()
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "books": db.execute("SELECT COUNT(*) FROM books").fetchone()[0],
        "donations": db.execute(
            "SELECT COUNT(*) FROM books WHERE listing_type = 'donation'"
        ).fetchone()[0],
        "exchanges": db.execute(
            "SELECT COUNT(*) FROM books WHERE listing_type = 'exchange'"
        ).fetchone()[0],
        "sales": db.execute(
            "SELECT COUNT(*) FROM books WHERE listing_type = 'sale'"
        ).fetchone()[0],
        "requests": db.execute("SELECT COUNT(*) FROM book_requests").fetchone()[0],
        "pending_tickets": db.execute(
            "SELECT COUNT(*) FROM support_tickets WHERE status IN ('Open', 'In Progress')"
        ).fetchone()[0],
        "resolved_tickets": db.execute(
            "SELECT COUNT(*) FROM support_tickets WHERE status = 'Resolved'"
        ).fetchone()[0],
    }
    return render_template(
        "admin.html", books=books, book_requests=book_requests,
        feedback_items=feedback_items, stats=stats,
        is_designated_admin=(
            current_user()["email"].casefold() == INITIAL_ADMIN_EMAIL.casefold()
        ),
        book_query=book_query, listing_type=listing_type,
        moderation_status=moderation_status, category_filter=category_filter,
        owner_filter=owner_filter, request_query=request_query,
        request_status_filter=request_status_filter,
        request_category_filter=request_category_filter,
        request_owner_filter=request_owner_filter,
    )


@app.route("/admin/users", methods=["GET", "POST"])
@designated_admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        try:
            user_id = int(request.form.get("user_id", ""))
        except ValueError:
            abort(400)
        result = db.execute(
            """UPDATE users SET is_active = 1 - is_active
               WHERE id = ? AND is_admin = 0 AND id != ?""",
            (user_id, current_user()["id"]),
        )
        if result.rowcount != 1:
            abort(400)
        log_admin_action(current_user()["id"], "account_status_toggled", "user", user_id)
        db.commit()
        sync_registered_users_csv()
        flash("Account status updated.", "success")
        return redirect(url_for("admin_users", q=request.form.get("q", "")[:100],
                                status=request.form.get("status", "")))

    query = request.args.get("q", "").strip()[:100]
    status_filter = request.args.get("status", "")
    if status_filter not in {"active", "suspended"}:
        status_filter = ""
    sql = """SELECT users.id, users.name, users.email, users.created_at,
                    users.is_admin, users.is_active, COUNT(books.id) AS listing_count
             FROM users LEFT JOIN books ON books.owner_id = users.id
             WHERE (? = '' OR users.name LIKE ? OR users.email LIKE ?)
               AND (? = '' OR (? = 'active' AND users.is_active = 1)
                    OR (? = 'suspended' AND users.is_active = 0))
             GROUP BY users.id
             ORDER BY users.created_at DESC, users.id DESC"""
    users = db.execute(
        sql, (query, f"%{query}%", f"%{query}%", status_filter,
              status_filter, status_filter)
    ).fetchall()
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return render_template(
        "admin_users.html", users=users, query=query,
        status_filter=status_filter, total_users=total_users,
        initial_admin_email=INITIAL_ADMIN_EMAIL,
    )


@app.route("/admin/books/<int:book_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_book(book_id):
    db = get_db()
    book = db.execute(
        """SELECT books.*, users.name AS owner_name, users.email AS owner_email
           FROM books JOIN users ON users.id = books.owner_id WHERE books.id = ?""",
        (book_id,),
    ).fetchone()
    if not book:
        abort(404)
    if request.method == "POST":
        replacement_image = None
        try:
            title = clean_text(request.form.get("title"), "Title", 120)
            author = clean_text(request.form.get("author"), "Author", 100)
            category = clean_text(request.form.get("category"), "Category", 40)
            condition = clean_text(request.form.get("condition"), "Condition", 20)
            location = clean_text(request.form.get("location"), "Location", 100)
            description = clean_text(request.form.get("description"), "Description", 1000, False)
            if category not in CATEGORIES or condition not in CONDITIONS:
                raise ValueError("Choose a valid category and condition.")
            price = book["price"]
            if book["listing_type"] == "sale":
                try:
                    price = float(request.form.get("price", ""))
                except ValueError as error:
                    raise ValueError("Enter a valid price in rupees.") from error
                if not 0 < price <= 100000:
                    raise ValueError("Price must be above ₹0 and no more than ₹100,000.")
            if request.files.get("image") and request.files["image"].filename:
                replacement_image = save_image_upload(request.files["image"])
            remove_image = request.form.get("remove_image") == "1"
            if replacement_image and remove_image:
                raise ValueError("Choose either a replacement photo or remove the current photo.")
            image_filename = (
                replacement_image if replacement_image
                else None if remove_image
                else book["image_filename"]
            )
            try:
                db.execute(
                    """UPDATE books SET title = ?, author = ?, category = ?, condition = ?,
                       location = ?, description = ?, price = ?, image_filename = ?
                       WHERE id = ?""",
                    (title, author, category, condition, location, description, price,
                     image_filename, book_id),
                )
                log_admin_action(
                    current_user()["id"], "listing_edited", "book", book_id,
                    f"owner_id={book['owner_id']}",
                )
                db.commit()
            except sqlite3.Error:
                db.rollback()
                remove_uploaded_image(replacement_image)
                raise
            if (book["image_filename"] and image_filename != book["image_filename"]):
                remove_uploaded_image(book["image_filename"])
            flash("Listing details updated.", "success")
            return redirect(url_for("admin_dashboard"))
        except ValueError as error:
            remove_uploaded_image(replacement_image)
            flash(str(error), "error")
    return render_template(
        "admin_edit_book.html", book=book, conditions=CONDITIONS, categories=CATEGORIES,
        is_admin=True,
    )


@app.route("/admin/users/<int:user_id>")
@designated_admin_required
def admin_user_detail(user_id):
    db = get_db()
    member = db.execute(
        """SELECT id, name, email, is_admin, is_active, created_at
           FROM users WHERE id = ?""",
        (user_id,),
    ).fetchone()
    if not member:
        abort(404)
    books = db.execute(
        "SELECT * FROM books WHERE owner_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    requests_list = db.execute(
        "SELECT * FROM book_requests WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    ).fetchall()
    return render_template(
        "admin_user_detail.html", member=member, books=books,
        requests_list=requests_list,
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        try:
            name = clean_text(request.form.get("name"), "Name", 80)
            email = clean_text(request.form.get("email"), "Email", 254).lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                raise ValueError("Enter a valid email address.")
            get_db().execute(
                "UPDATE users SET name = ?, email = ? WHERE id = ?",
                (name, email, user["id"]),
            )
            get_db().commit()
            sync_registered_users_csv()
            g.pop("current_user", None)
            flash("Your profile was updated.", "success")
            return redirect(url_for("profile"))
        except sqlite3.IntegrityError:
            get_db().rollback()
            flash("That email address is already in use.", "error")
        except ValueError as error:
            flash(str(error), "error")
    profile_user = get_db().execute(
        "SELECT name, email, created_at FROM users WHERE id = ?", (user["id"],)
    ).fetchone()
    return render_template("profile.html", profile_user=profile_user)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We could not find that page or listing."), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "That request could not be processed.")), 400


@app.errorhandler(413)
def request_too_large(_error):
    return render_template(
        "error.html",
        code=413,
        message="The upload is too large. Keep each image at or below 10 MB and try again.",
    ), 413


init_db()
sync_registered_users_csv()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
