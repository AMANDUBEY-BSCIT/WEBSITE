import gc
import io
import os
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from PIL import Image
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-for-unit-tests")

import app as bookbridge


class BookBridgeWorkflowTests(unittest.TestCase):
    def test_secret_key_is_generated_once_and_existing_key_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = Path(temporary_directory) / ".env"
            with patch.dict(os.environ, {}, clear=True):
                generated_key = bookbridge.load_secret_key(env_file)
                self.assertRegex(generated_key, r"^[0-9a-f]{64}$")
                self.assertEqual(bookbridge.load_secret_key(env_file), generated_key)

            existing_key = "pre-existing-local-secret"
            env_file.write_text(f"SECRET_KEY={existing_key}\n", encoding="utf-8")
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(bookbridge.load_secret_key(env_file), existing_key)
            self.assertEqual(env_file.read_text(encoding="utf-8"), f"SECRET_KEY={existing_key}\n")

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "test.sqlite3"
        self.upload_directory = Path(self.temporary_directory.name) / "uploads"
        bookbridge.app.config.update(
            TESTING=True,
            DATABASE=str(self.database_path),
            UPLOAD_FOLDER=str(self.upload_directory),
        )
        with patch.dict("os.environ", {"ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}):
            bookbridge.init_db()
        self.client = bookbridge.app.test_client()

    def tearDown(self):
        gc.collect()
        self.temporary_directory.cleanup()

    def csrf(self, client, path):
        response = client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match, f"No CSRF token found on {path}")
        return match.group(1).decode()

    def png_image(self, size=(3, 7)):
        image_data = io.BytesIO()
        Image.new("RGB", size, color=(34, 95, 62)).save(image_data, format="PNG")
        image_data.seek(0)
        return image_data

    def test_image_validation_accepts_supported_formats_with_matching_extensions(self):
        supported_formats = (
            ("jpg", "JPEG", "image/jpeg"),
            ("jpeg", "JPEG", "image/jpeg"),
            ("png", "PNG", "image/png"),
            ("webp", "WEBP", "image/webp"),
            ("gif", "GIF", "image/gif"),
            ("bmp", "BMP", "image/bmp"),
        )
        for extension, image_format, mime_type in supported_formats:
            with self.subTest(extension=extension):
                image_data = io.BytesIO()
                Image.new("RGB", (7, 3), color=(34, 95, 62)).save(image_data, format=image_format)
                image_data.seek(0)
                upload = FileStorage(
                    stream=image_data,
                    filename=f"sample.{extension}",
                    content_type=mime_type,
                )
                with bookbridge.app.app_context():
                    filename = bookbridge.save_image_upload(upload)
                self.assertTrue(filename.endswith(f".{extension}"))
                with Image.open(self.upload_directory / filename) as saved_image:
                    self.assertEqual(saved_image.format, image_format)
                image_data.close()

    def create_user(self, email, password="existing-password-123"):
        with bookbridge.app.app_context():
            database = bookbridge.get_db()
            database.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                ("Reset Reader", email, generate_password_hash(password), bookbridge.utc_now()),
            )
            database.commit()
            return database.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()["id"]

    def request_reset_code(self, client, email):
        token = self.csrf(client, "/forgot-password")
        return client.post(
            "/forgot-password",
            data={"csrf_token": token, "email": email},
            follow_redirects=True,
        )

    def signup(self, client, name, email):
        token = self.csrf(client, "/signup")
        response = client.post("/signup", data={
            "csrf_token": token,
            "name": name,
            "email": email,
            "password": "a-Long-test-password1",
            "confirm_password": "a-Long-test-password1",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your account is ready", response.data)

    def add_exchange_book(self, client, title):
        token = self.csrf(client, "/exchange/list")
        response = client.post("/exchange/list", data={
            "csrf_token": token,
            "title": title,
            "author": "Test Author",
            "category": "Novels",
            "condition": "Good",
            "location": "Pune",
            "description": "Workflow test listing",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with bookbridge.app.app_context():
            return bookbridge.get_db().execute("SELECT id FROM books WHERE title = ?", (title,)).fetchone()["id"]

    def test_signup_donation_browse_request_and_enquiry(self):
        self.signup(self.client, "Reader One", "reader1@example.test")
        token = self.csrf(self.client, "/donate")
        response = self.client.post("/donate", data={
            "csrf_token": token,
            "title": "A Donated Book",
            "author": "A. Writer",
            "category": "Fiction",
            "condition": "Good",
            "location": "Pune",
            "description": "A copy looking for its next reader",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"A Donated Book", self.client.get("/books?q=Donated").data)
        with bookbridge.app.app_context():
            book_id = bookbridge.get_db().execute("SELECT id FROM books WHERE title = ?", ("A Donated Book",)).fetchone()["id"]
        second_reader = bookbridge.app.test_client()
        self.signup(second_reader, "Reader Two", "reader2@example.test")
        token = self.csrf(second_reader, "/requests")
        response = second_reader.post("/requests", data={
            "csrf_token": token, "title": "Requested Book", "author": "Some Author",
            "category": "Academic", "location": "Pune", "message": "For a course",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Requested Book", response.data)
        token = self.csrf(second_reader, f"/books/{book_id}")
        response = second_reader.post("/enquiries", data={
            "csrf_token": token, "book_id": str(book_id), "message": "Is this copy available?",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your enquiry was sent", response.data)

    def test_listing_images_and_all_requested_conditions(self):
        self.signup(self.client, "Photo Reader", "photo-reader@example.test")
        listing_routes = (
            ("donation", "/donate", "New"),
            ("sale", "/sell", "Like New"),
            ("exchange", "/exchange/list", "Very Good"),
        )
        book_ids = []
        conditions = ["New", "Like New", "Very Good", "Good", "Acceptable", "Heavily Used", "Damaged"]

        for index, (listing_type, path, condition) in enumerate(listing_routes, start=1):
            form_page = self.client.get(path)
            for label in conditions:
                self.assertIn(f">{label}</option>".encode(), form_page.data)
            self.assertIn(b"maximum 10 MB", form_page.data)
            self.assertIn(b"data-image-preview", form_page.data)
            self.assertIn(b"enctype=\"multipart/form-data\"", form_page.data)

            image_data = self.png_image(((3, 7), (7, 3), (5, 5))[index - 1])
            form_data = {
                "csrf_token": self.csrf(self.client, path),
                "title": f"Photo Listing {index}",
                "author": "A. Writer",
                "category": "Fiction",
                "condition": condition,
                "location": "Pune",
                "description": "Test listing with varied photo aspect ratios",
                "image": (image_data, f"book-{index}.png", "image/png"),
            }
            if listing_type == "sale":
                form_data["price"] = "25"
            response = self.client.post(path, data=form_data, follow_redirects=True)
            image_data.close()
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Your book listing is now live.", response.data)

        with bookbridge.app.app_context():
            books = bookbridge.get_db().execute(
                "SELECT id, title, condition, image_filename FROM books ORDER BY id"
            ).fetchall()
            self.assertEqual([book["condition"] for book in books], ["New", "Like New", "Very Good"])
            self.assertTrue(all(book["image_filename"] for book in books))
            book_ids = [book["id"] for book in books]
            filenames = [book["image_filename"] for book in books]
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{32}\.png", filename) for filename in filenames))

        browse_response = self.client.get("/books")
        self.assertIn(b"Photo Listing 1", browse_response.data)
        self.assertIn(b"New", browse_response.data)
        self.assertIn(b"book-cover-image", browse_response.data)
        dashboard_response = self.client.get("/dashboard")
        self.assertIn(b"dashboard-book-thumb", dashboard_response.data)
        self.assertIn(b"Like New", dashboard_response.data)

        for book_id, filename, condition in zip(book_ids, filenames, ("New", "Like New", "Very Good")):
            detail_response = self.client.get(f"/books/{book_id}")
            self.assertEqual(detail_response.status_code, 200)
            self.assertIn(f"Photo of Photo Listing {book_id}".encode(), detail_response.data)
            self.assertIn(condition.encode(), detail_response.data)
            image_response = self.client.get(f"/uploads/{filename}")
            self.assertEqual(image_response.status_code, 200)
            self.assertEqual(image_response.mimetype, "image/png")
            self.assertEqual(image_response.headers["X-Content-Type-Options"], "nosniff")
            image_response.close()

        with bookbridge.app.app_context():
            with patch.dict("os.environ", {"ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}):
                bookbridge.init_db()
            persisted_names = bookbridge.get_db().execute(
                "SELECT image_filename FROM books ORDER BY id"
            ).fetchall()
            self.assertEqual([row["image_filename"] for row in persisted_names], filenames)
        self.assertTrue(all((self.upload_directory / filename).is_file() for filename in filenames))

    def test_upload_rejects_oversized_unsupported_mismatched_and_corrupt_images(self):
        self.signup(self.client, "Upload Reader", "upload-reader@example.test")
        invalid_uploads = (
            ("oversized.png", "image/png", io.BytesIO(b"x" * (bookbridge.UPLOAD_MAX_BYTES + 1)),
             "Each image must be 10 MB or smaller."),
            ("unsupported.svg", "image/svg+xml", io.BytesIO(b"<svg></svg>"),
             "Choose a JPG, JPEG, PNG, WEBP, GIF, or BMP image."),
            ("unsupported.heic", "image/heic", io.BytesIO(b"unsupported format"),
             "Choose a JPG, JPEG, PNG, WEBP, GIF, or BMP image."),
            ("mismatch.jpg", "image/jpeg", self.png_image(),
             "The image content does not match its file extension."),
            ("mime-mismatch.png", "image/jpeg", self.png_image(),
             "The image content type does not match the selected file."),
            ("corrupt.png", "image/png", io.BytesIO(b"not an image"),
             "That image is invalid or damaged."),
        )
        for filename, mime_type, image_data, expected_message in invalid_uploads:
            with self.subTest(filename=filename):
                response = self.client.post("/donate", data={
                    "csrf_token": self.csrf(self.client, "/donate"),
                    "title": "Rejected Upload",
                    "author": "A. Writer",
                    "category": "Fiction",
                    "condition": "Good",
                    "location": "Pune",
                    "image": (image_data, filename, mime_type),
                }, follow_redirects=True)
                image_data.close()
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected_message.encode(), response.data)
                response.close()

        missing_condition = self.client.post("/donate", data={
            "csrf_token": self.csrf(self.client, "/donate"),
            "title": "No Condition",
            "author": "A. Writer",
            "category": "Fiction",
            "location": "Pune",
        })
        self.assertEqual(missing_condition.status_code, 200)
        self.assertIn(b"Condition is required.", missing_condition.data)
        with bookbridge.app.app_context():
            self.assertEqual(
                bookbridge.get_db().execute(
                    "SELECT COUNT(*) AS total FROM books WHERE title IN ('Rejected Upload', 'No Condition')"
                ).fetchone()["total"],
                0,
            )
        self.assertFalse(list(self.upload_directory.glob("*")) if self.upload_directory.exists() else [])

    def test_request_and_enquiry_image_attachments(self):
        owner = self.client
        self.signup(owner, "Attachment Owner", "attachment-owner@example.test")
        token = self.csrf(owner, "/donate")
        owner.post("/donate", data={
            "csrf_token": token,
            "title": "Attachment Listing",
            "author": "A. Writer",
            "category": "Fiction",
            "condition": "Good",
            "location": "Pune",
        }, follow_redirects=True)
        with bookbridge.app.app_context():
            book_id = bookbridge.get_db().execute(
                "SELECT id FROM books WHERE title = ?", ("Attachment Listing",)
            ).fetchone()["id"]

        buyer = bookbridge.app.test_client()
        self.signup(buyer, "Attachment Buyer", "attachment-buyer@example.test")
        request_response = buyer.get("/requests")
        self.assertIn(b"Optional image attachment", request_response.data)
        token = self.csrf(buyer, "/requests")
        request_image = self.png_image()
        response = buyer.post("/requests", data={
            "csrf_token": token,
            "title": "Request with image",
            "category": "Fiction",
            "location": "Pune",
            "attachment": (request_image, "request.png", "image/png"),
        }, follow_redirects=True)
        request_image.close()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"request-attachment", response.data)

        detail_response = buyer.get(f"/books/{book_id}")
        self.assertIn(b"Optional image attachment", detail_response.data)
        token = self.csrf(buyer, f"/books/{book_id}")
        enquiry_image = self.png_image()
        response = buyer.post("/enquiries", data={
            "csrf_token": token,
            "book_id": str(book_id),
            "message": "Please see the attached reference image.",
            "attachment": (enquiry_image, "enquiry.png", "image/png"),
        }, follow_redirects=True)
        enquiry_image.close()
        self.assertEqual(response.status_code, 200)
        with bookbridge.app.app_context():
            enquiry = bookbridge.get_db().execute(
                "SELECT id, attachment_filename FROM enquiries WHERE book_id = ?", (book_id,)
            ).fetchone()
            self.assertTrue(enquiry["attachment_filename"])
        self.assertIn(b"dashboard-attachment", buyer.get("/dashboard").data)
        self.assertIn(b"dashboard-attachment", owner.get("/dashboard").data)

        image_path = f"/uploads/{enquiry['attachment_filename']}"
        buyer_image = buyer.get(image_path)
        self.assertEqual(buyer_image.status_code, 200)
        buyer_image.close()
        owner_image = owner.get(image_path)
        self.assertEqual(owner_image.status_code, 200)
        owner_image.close()
        stranger = bookbridge.app.test_client()
        self.signup(stranger, "Attachment Stranger", "attachment-stranger@example.test")
        self.assertEqual(stranger.get(image_path).status_code, 404)
        self.assertEqual(bookbridge.app.test_client().get(image_path).status_code, 404)

    def test_existing_database_rows_survive_additive_upload_schema_migration(self):
        legacy_path = Path(self.temporary_directory.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_path) as legacy_db:
            legacy_db.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
                    password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
                    is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
                );
                CREATE TABLE books (
                    id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, title TEXT NOT NULL,
                    author TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                    condition TEXT NOT NULL, location TEXT NOT NULL, price REAL NOT NULL DEFAULT 0,
                    listing_type TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
                );
                CREATE TABLE book_requests (
                    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL,
                    author TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, location TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '', is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE enquiries (
                    id INTEGER PRIMARY KEY, book_id INTEGER NOT NULL, sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
                );
                INSERT INTO users VALUES (1, 'Legacy Reader', 'legacy@example.test', 'hash', 0, 1, '2024-01-01');
                INSERT INTO books VALUES (1, 1, 'Existing Book', 'Writer', 'Fiction', '',
                    'Very good', 'Pune', 0, 'donation', 1, '2024-01-01');
                INSERT INTO book_requests VALUES (1, 1, 'Existing Request', '', 'Fiction',
                    'Pune', '', 1, '2024-01-01');
                INSERT INTO enquiries VALUES (1, 1, 1, 1, 'Existing enquiry', '2024-01-01');
                """
            )

        bookbridge.app.config["DATABASE"] = str(legacy_path)
        with patch.dict("os.environ", {"ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}):
            bookbridge.init_db()
        with sqlite3.connect(legacy_path) as migrated_db:
            book_row = migrated_db.execute(
                "SELECT title, condition, image_filename FROM books WHERE id = 1"
            ).fetchone()
            request_row = migrated_db.execute(
                "SELECT title, attachment_filename FROM book_requests WHERE id = 1"
            ).fetchone()
            enquiry_row = migrated_db.execute(
                "SELECT message, attachment_filename FROM enquiries WHERE id = 1"
            ).fetchone()
        self.assertEqual(book_row, ("Existing Book", "Very good", None))
        self.assertEqual(request_row, ("Existing Request", None))
        self.assertEqual(enquiry_row, ("Existing enquiry", None))
        with sqlite3.connect(legacy_path) as migrated_db:
            migrated_tables = {
                row[0] for row in migrated_db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertIn("support_tickets", migrated_tables)
        self.assertIn("support_ticket_messages", migrated_tables)

    def test_private_enquiry_conversation_unread_counts_and_persistence(self):
        owner_client = self.client
        self.signup(owner_client, "Listing Owner", "listing-owner@example.test")
        token = self.csrf(owner_client, "/donate")
        response = owner_client.post("/donate", data={
            "csrf_token": token,
            "title": "Conversation Book",
            "author": "A. Writer",
            "category": "Fiction",
            "condition": "Good",
            "location": "Pune",
            "description": "A listing for private conversation tests",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        with bookbridge.app.app_context():
            book_id = bookbridge.get_db().execute(
                "SELECT id FROM books WHERE title = ?", ("Conversation Book",)
            ).fetchone()["id"]

        buyer_client = bookbridge.app.test_client()
        self.signup(buyer_client, "Interested Buyer", "buyer@example.test")
        token = self.csrf(buyer_client, f"/books/{book_id}")
        response = buyer_client.post("/enquiries", data={
            "csrf_token": token,
            "book_id": str(book_id),
            "message": "Is this book still available?",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your enquiry was sent", response.data)

        with bookbridge.app.app_context():
            enquiry_id = bookbridge.get_db().execute(
                "SELECT id FROM enquiries WHERE book_id = ?", (book_id,)
            ).fetchone()["id"]

        owner_dashboard = owner_client.get("/dashboard")
        self.assertIn(
            f'href="/messages/{enquiry_id}">Chat / Reply'.encode(),
            owner_dashboard.data,
        )
        self.assertIn(b"Messages", owner_dashboard.data)
        buyer_inbox = buyer_client.get("/messages")
        self.assertEqual(buyer_inbox.status_code, 200)
        self.assertIn(b"Conversation Book", buyer_inbox.data)
        self.assertIn(b"Is this book still available?", buyer_inbox.data)

        token = self.csrf(owner_client, f"/messages/{enquiry_id}")
        response = owner_client.post(
            f"/messages/{enquiry_id}",
            data={"csrf_token": token, "body": "Yes, it is available."},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Is this book still available?", response.data)
        self.assertIn(b"Yes, it is available.", response.data)
        self.assertIn(b"Listing Owner", response.data)
        self.assertIn(b"Interested Buyer", response.data)
        self.assertIn(b"Original enquiry", response.data)
        self.assertIn(b"datetime=", response.data)

        buyer_inbox = buyer_client.get("/messages")
        self.assertIn(b"1 unread", buyer_inbox.data)
        self.assertIn(b'class="unread-badge">1</span>', buyer_inbox.data)
        buyer_thread = buyer_client.get(f"/messages/{enquiry_id}")
        self.assertEqual(buyer_thread.status_code, 200)
        self.assertIn(b"Yes, it is available.", buyer_thread.data)
        self.assertNotIn(b"1 unread", buyer_client.get("/messages").data)

        token = self.csrf(buyer_client, f"/messages/{enquiry_id}")
        response = buyer_client.post(
            f"/messages/{enquiry_id}",
            data={"csrf_token": token, "body": "Could we arrange a hand-off this weekend?"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Could we arrange a hand-off this weekend?", response.data)
        self.assertIn(b"1 unread", owner_client.get("/messages").data)
        owner_thread = owner_client.get(f"/messages/{enquiry_id}")
        self.assertIn(b"Could we arrange a hand-off this weekend?", owner_thread.data)

        stranger_client = bookbridge.app.test_client()
        self.signup(stranger_client, "Unrelated Reader", "stranger@example.test")
        self.assertEqual(stranger_client.get(f"/messages/{enquiry_id}").status_code, 404)
        token = self.csrf(stranger_client, "/messages")
        denied_post = stranger_client.post(
            f"/messages/{enquiry_id}",
            data={"csrf_token": token, "body": "This should not be stored."},
        )
        self.assertEqual(denied_post.status_code, 404)
        anonymous_client = bookbridge.app.test_client()
        self.assertEqual(anonymous_client.get(f"/messages/{enquiry_id}").status_code, 302)

        with bookbridge.app.app_context():
            with patch.dict("os.environ", {"ADMIN_EMAIL": "", "ADMIN_PASSWORD": ""}):
                bookbridge.init_db()
            stored_messages = bookbridge.get_db().execute(
                "SELECT body FROM messages WHERE enquiry_id = ? ORDER BY id", (enquiry_id,)
            ).fetchall()
            self.assertEqual(
                [message["body"] for message in stored_messages],
                ["Yes, it is available.", "Could we arrange a hand-off this weekend?"],
            )

    def test_signup_requires_a_strong_password_and_confirmation(self):
        token = self.csrf(self.client, "/signup")
        response = self.client.post("/signup", data={
            "csrf_token": token,
            "name": "Short Password",
            "email": "short@example.test",
            "password": "abc1234",
            "confirm_password": "abc1234",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please choose a stronger password.", response.data)

        token = self.csrf(self.client, "/signup")
        response = self.client.post("/signup", data={
            "csrf_token": token,
            "name": "Eight Characters",
            "email": "eight@example.test",
            "password": "Abc12345",
            "confirm_password": "Abc12345",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

    def test_exchange_offer_acceptance_and_status_tracking(self):
        first_reader = self.client
        self.signup(first_reader, "Owner", "owner@example.test")
        target_id = self.add_exchange_book(first_reader, "Offered Target")
        second_reader = bookbridge.app.test_client()
        self.signup(second_reader, "Offerer", "offerer@example.test")
        offered_id = self.add_exchange_book(second_reader, "Offerer Book")
        token = self.csrf(second_reader, f"/books/{target_id}")
        response = second_reader.post("/exchange/offers", data={
            "csrf_token": token, "book_id": str(target_id), "offered_book_id": str(offered_id),
            "message": "Would you like to swap?",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with bookbridge.app.app_context():
            offer_id = bookbridge.get_db().execute("SELECT id FROM exchange_offers").fetchone()["id"]
        token = self.csrf(first_reader, "/dashboard")
        response = first_reader.post(f"/exchange/offers/{offer_id}/accept", data={"csrf_token": token}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Accepted", response.data)
        token = self.csrf(second_reader, "/dashboard")
        self.assertIn(b"Accepted", second_reader.get("/dashboard").data)

    def test_csrf_rejects_a_post_without_token(self):
        response = self.client.post("/signup", data={"name": "No Token"})
        self.assertEqual(response.status_code, 400)

    def test_auth_forms_discourage_autofill_and_preserve_signup_validation(self):
        login_page = self.client.get("/login")
        self.assertIn(b'href="/forgot-password">Forgot password?</a>', login_page.data)
        self.assertIn(b'<form method="post" class="stack-form" autocomplete="off" novalidate data-auth-form data-clear-on-load="true">', login_page.data)
        self.assertIn(b'name="email" type="email" autocomplete="off"', login_page.data)
        self.assertIn(b'name="password" type="password" autocomplete="new-password"', login_page.data)
        self.assertIn(b'data-password-toggle aria-controls="login-password"', login_page.data)

        signup_page = self.client.get("/signup")
        self.assertIn(b'<form method="post" class="stack-form" autocomplete="off" novalidate data-auth-form data-clear-on-load="true">', signup_page.data)
        self.assertIn(b'name="email" type="email" required maxlength="254" autocomplete="email"', signup_page.data)
        self.assertIn(b'name="password" type="password" required minlength="8" maxlength="128" autocomplete="new-password"', signup_page.data)
        self.assertIn(b'name="confirm_password" type="password"', signup_page.data)
        self.assertIn(b">Register</a>", self.client.get("/").data)

        token = self.csrf(self.client, "/signup")
        invalid_signup = self.client.post("/signup", data={
            "csrf_token": token,
            "name": "Validation Reader",
            "email": "existing@example.test",
            "password": "short",
            "confirm_password": "short",
        })
        self.assertEqual(invalid_signup.status_code, 200)
        self.assertIn(b'data-clear-on-load="false"', invalid_signup.data)
        self.assertIn(b'value="Validation Reader"', invalid_signup.data)
        self.assertIn(b'value="existing@example.test"', invalid_signup.data)
        self.assertNotIn(b'value="short"', invalid_signup.data)
        self.assertIn(b"Please choose a stronger password.", invalid_signup.data)

    def test_login_validation_preserves_email_and_clears_password(self):
        valid_password = "Strong-Test-Password1"
        self.create_user("login-reader@example.test", valid_password)
        with bookbridge.app.app_context():
            stored_hash = bookbridge.get_db().execute(
                "SELECT password_hash FROM users WHERE email = ?",
                ("login-reader@example.test",),
            ).fetchone()["password_hash"]
        token = self.csrf(self.client, "/login")
        wrong_password = self.client.post("/login", data={
            "csrf_token": token,
            "email": "login-reader@example.test",
            "password": "incorrect",
        })
        self.assertEqual(wrong_password.status_code, 200)
        self.assertIn(b'value="login-reader@example.test"', wrong_password.data)
        self.assertIn(b"Incorrect password. Please try again.", wrong_password.data)
        self.assertIn(b'id="login-password" name="password" type="password"', wrong_password.data)
        self.assertIn(b'autofocus', wrong_password.data)
        self.assertNotIn(b'value="incorrect"', wrong_password.data)

        token = self.csrf(self.client, "/login")
        unknown_email = self.client.post("/login", data={
            "csrf_token": token,
            "email": "unknown-reader@example.test",
            "password": "incorrect",
        })
        self.assertIn(b'Invalid email or password.', unknown_email.data)
        self.assertIn(b'value="unknown-reader@example.test"', unknown_email.data)

        token = self.csrf(self.client, "/login")
        invalid_email = self.client.post("/login", data={
            "csrf_token": token, "email": "not-an-email", "password": "incorrect",
        })
        self.assertIn(b"Please enter a valid email address.", invalid_email.data)
        self.assertNotIn(b'value="incorrect"', invalid_email.data)

        token = self.csrf(self.client, "/login")
        empty_fields = self.client.post("/login", data={"csrf_token": token})
        self.assertIn(b"Please enter your email address.", empty_fields.data)
        self.assertIn(b"Please enter your password.", empty_fields.data)

        token = self.csrf(self.client, "/login")
        successful_login = self.client.post("/login", data={
            "csrf_token": token,
            "email": "login-reader@example.test",
            "password": valid_password,
        })
        self.assertEqual(successful_login.status_code, 302)
        self.assertEqual(successful_login.headers["Location"], "/")
        self.assertTrue(check_password_hash(stored_hash, valid_password))

    def test_registration_validates_fields_confirmation_and_hashes_password(self):
        token = self.csrf(self.client, "/signup")
        invalid = self.client.post("/signup", data={
            "csrf_token": token,
            "name": "",
            "email": "not-an-email",
            "password": "weak",
            "confirm_password": "different",
        })
        self.assertIn(b"Please enter your full name.", invalid.data)
        self.assertIn(b"Please enter a valid email address.", invalid.data)
        self.assertIn(b"Please choose a stronger password.", invalid.data)
        self.assertIn(b"Passwords do not match.", invalid.data)
        self.assertNotIn(b'value="weak"', invalid.data)
        self.assertNotIn(b'value="different"', invalid.data)

        password = "Stronger-Reader-Password7"
        token = self.csrf(self.client, "/signup")
        created = self.client.post("/signup", data={
            "csrf_token": token, "name": "New Reader",
            "email": "new-reader@example.test",
            "password": password, "confirm_password": password,
        })
        self.assertEqual(created.status_code, 302)
        with bookbridge.app.app_context():
            user = bookbridge.get_db().execute(
                "SELECT password_hash FROM users WHERE email = ?",
                ("new-reader@example.test",),
            ).fetchone()
        self.assertTrue(check_password_hash(user["password_hash"], password))
        self.assertNotEqual(user["password_hash"], password)

        another = bookbridge.app.test_client()
        token = self.csrf(another, "/signup")
        duplicate = another.post("/signup", data={
            "csrf_token": token,
            "name": "Duplicate Reader",
            "email": "new-reader@example.test",
            "password": password, "confirm_password": password,
        })
        self.assertIn(
            b"This email cannot be used for a new registration.", duplicate.data
        )
        self.assertIn(b'value="Duplicate Reader"', duplicate.data)
        self.assertNotIn(password.encode(), duplicate.data)

    def test_password_visibility_controls_exist_for_all_password_forms(self):
        signup_page = self.client.get("/signup")
        self.assertEqual(signup_page.data.count(b'data-password-toggle'), 2)
        home_page = self.client.get("/")
        self.assertIn(b">Register</a>", home_page.data)
        self.assertNotIn(b"Join the community", home_page.data)
        user_id = self.create_user("reset-reader@example.test", "Initial-Password7")
        with bookbridge.app.app_context():
            database = bookbridge.get_db()
            reset_id = database.execute(
                """INSERT INTO password_reset_tokens
                   (user_id, otp_hash, expires_at) VALUES (?, '', ?)""",
                (user_id, bookbridge.time.time() + 300),
            ).lastrowid
            grant = "test-verified-reset-grant"
            database.execute(
                """UPDATE password_reset_tokens SET verification_hash = ?,
                   verification_expires_at = ? WHERE id = ?""",
                (bookbridge._password_reset_digest("grant", reset_id, grant),
                 bookbridge.time.time() + 300, reset_id),
            )
            database.commit()
        with self.client.session_transaction() as current_session:
            current_session["password_reset_id"] = reset_id
            current_session["password_reset_grant"] = grant
        reset_page = self.client.get("/reset-password")
        self.assertEqual(reset_page.data.count(b'data-password-toggle'), 2)

        change_client = bookbridge.app.test_client()
        token = self.csrf(change_client, "/login")
        change_client.post("/login", data={
            "csrf_token": token, "email": "reset-reader@example.test",
            "password": "Initial-Password7",
        })
        change_page = change_client.get("/change-password")
        self.assertEqual(change_page.status_code, 200)
        self.assertEqual(change_page.data.count(b'data-password-toggle'), 3)

    def test_change_password_verifies_current_password_and_updates_hash(self):
        old_password = "Old-Reader-Password9"
        new_password = "New-Reader-Password8"
        self.create_user("change-reader@example.test", old_password)
        client = bookbridge.app.test_client()
        token = self.csrf(client, "/login")
        client.post("/login", data={
            "csrf_token": token, "email": "change-reader@example.test",
            "password": old_password,
        })
        token = self.csrf(client, "/change-password")
        wrong_current = client.post("/change-password", data={
            "csrf_token": token, "current_password": "not-current",
            "password": new_password, "confirm_password": new_password,
        })
        self.assertIn(b"Your current password is incorrect.", wrong_current.data)
        self.assertNotIn(new_password.encode(), wrong_current.data)

        token = self.csrf(client, "/change-password")
        changed = client.post("/change-password", data={
            "csrf_token": token, "current_password": old_password,
            "password": new_password, "confirm_password": new_password,
        })
        self.assertEqual(changed.status_code, 302)
        with bookbridge.app.app_context():
            stored_hash = bookbridge.get_db().execute(
                "SELECT password_hash FROM users WHERE email = ?",
                ("change-reader@example.test",),
            ).fetchone()["password_hash"]
        self.assertTrue(check_password_hash(stored_hash, new_password))
        self.assertFalse(check_password_hash(stored_hash, old_password))

    def test_designated_admin_user_management_and_password_free_export(self):
        designated_hash = generate_password_hash("Test-Admin-Password7")
        with bookbridge.app.app_context():
            database = bookbridge.get_db()
            database.execute(
                """INSERT INTO users (name, email, password_hash, is_admin, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                ("Designated Admin", bookbridge.INITIAL_ADMIN_EMAIL,
                 designated_hash, bookbridge.utc_now()),
            )
            database.execute(
                """INSERT INTO users (name, email, password_hash, created_at)
                   VALUES (?, ?, ?, ?)""",
                ("Directory Member", "directory-member@example.test",
                 generate_password_hash("Another-Password7"), bookbridge.utc_now()),
            )
            database.execute(
                """INSERT INTO users
                   (name, email, password_hash, is_admin, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                ("Other Admin", "other-admin@example.test",
                 generate_password_hash("Other-Admin-Password8"), bookbridge.utc_now()),
            )
            database.commit()
            directory_member_id = database.execute(
                "SELECT id FROM users WHERE email = ?",
                ("directory-member@example.test",),
            ).fetchone()["id"]
        admin = bookbridge.app.test_client()
        token = self.csrf(admin, "/login")
        admin.post("/login", data={
            "csrf_token": token,
            "email": bookbridge.INITIAL_ADMIN_EMAIL,
            "password": "Test-Admin-Password7",
        })
        directory_client = bookbridge.app.test_client()
        token = self.csrf(directory_client, "/login")
        directory_client.post("/login", data={
            "csrf_token": token,
            "email": "directory-member@example.test",
            "password": "Another-Password7",
        })
        self.add_exchange_book(directory_client, "Directory Test Listing")
        users_page = admin.get("/admin/users")
        self.assertEqual(users_page.status_code, 200)
        self.assertIn(b"Total registered users", users_page.data)
        self.assertIn(b"User ID", users_page.data)
        self.assertIn(b"directory-member@example.test", users_page.data)
        self.assertIn(b"Directory Test Listing", admin.get(
            f"/admin/users/{directory_member_id}"
        ).data)
        self.assertNotIn(b"password_hash", users_page.data)
        self.assertNotIn(designated_hash.encode(), users_page.data)
        self.assertIn(
            b"Directory Member",
            admin.get("/admin/users?q=Directory&status=active").data,
        )

        token = self.csrf(admin, "/admin/users")
        suspended = admin.post("/admin/users", data={
            "csrf_token": token, "user_id": str(directory_member_id),
        })
        self.assertEqual(suspended.status_code, 302)
        self.assertIn(
            b"Suspended",
            admin.get("/admin/users?status=suspended").data,
        )
        token = self.csrf(admin, "/admin/users")
        reactivated = admin.post("/admin/users", data={
            "csrf_token": token, "user_id": str(directory_member_id),
        })
        self.assertEqual(reactivated.status_code, 302)

        regular = bookbridge.app.test_client()
        self.signup(regular, "Regular Member", "regular-user@example.test")
        self.assertEqual(regular.get("/admin/users").status_code, 403)
        self.assertEqual(
            regular.get("/admin/users/1").status_code, 403
        )
        other_admin = bookbridge.app.test_client()
        token = self.csrf(other_admin, "/login")
        other_admin.post("/login", data={
            "csrf_token": token, "email": "other-admin@example.test",
            "password": "Other-Admin-Password8",
        })
        self.assertEqual(other_admin.get("/admin/users").status_code, 403)

        output_file = self.database_path.parent / "admin_exports" / "registered_users.csv"
        self.assertFalse(output_file.exists())
        runner = bookbridge.app.test_cli_runner()
        denied_export = runner.invoke(
            args=[
                "export-registered-users",
                "--confirm-email", "someone-else@example.test",
            ]
        )
        self.assertNotEqual(denied_export.exit_code, 0)
        self.assertFalse(output_file.exists())
        wrong_password_export = runner.invoke(
            args=[
                "export-registered-users",
                "--confirm-email", bookbridge.INITIAL_ADMIN_EMAIL,
            ],
            input="wrong-password\n",
        )
        self.assertNotEqual(wrong_password_export.exit_code, 0)
        self.assertFalse(output_file.exists())
        exported = runner.invoke(
            args=[
                "export-registered-users",
                "--confirm-email", bookbridge.INITIAL_ADMIN_EMAIL,
            ],
            input="Test-Admin-Password7\n",
        )
        self.assertEqual(exported.exit_code, 0, exported.output)
        csv_content = output_file.read_text(encoding="utf-8")
        self.assertIn("User ID,Full Name,Email,Registration Date,Role,Account Status", csv_content)
        self.assertIn("directory-member@example.test", csv_content)
        self.assertNotIn("password_hash", csv_content)
        self.assertNotIn(designated_hash, csv_content)

    def test_password_recovery_pages_render(self):
        forgot_page = self.client.get("/forgot-password")
        self.assertEqual(forgot_page.status_code, 200)
        self.assertIn(b'name="otp"', forgot_page.data)
        self.assertIn(b'action="/reset-password/verify"', forgot_page.data)
        self.assertEqual(self.client.get("/reset-password").status_code, 302)

    def test_password_reset_sends_code_generically_and_enforces_resend_cooldown(self):
        self.create_user("reset-reader@example.test")
        with patch.object(bookbridge, "send_password_reset_email") as send_email:
            known_response = self.request_reset_code(self.client, "reset-reader@example.test")
            unknown_response = self.request_reset_code(self.client, "unknown@example.test")
            cooldown_response = self.request_reset_code(self.client, "reset-reader@example.test")

        generic_message = bookbridge.PASSWORD_RESET_GENERIC_MESSAGE.encode()
        self.assertIn(generic_message, known_response.data)
        self.assertIn(generic_message, unknown_response.data)
        self.assertIn(generic_message, cooldown_response.data)
        self.assertEqual(send_email.call_count, 1)
        otp = send_email.call_args.args[1]
        self.assertRegex(otp, r"^\d{6}$")
        for response in (known_response, unknown_response, cooldown_response):
            self.assertNotIn(otp.encode(), response.data)
        self.assertNotIn(b"reset-reader@example.test", known_response.data)

    def test_password_reset_rejects_invalid_and_reused_codes_then_updates_password_hash(self):
        user_id = self.create_user("reset-reader@example.test")
        with patch.object(bookbridge, "send_password_reset_email") as send_email:
            response = self.request_reset_code(self.client, "reset-reader@example.test")
        self.assertIn(bookbridge.PASSWORD_RESET_GENERIC_MESSAGE.encode(), response.data)
        otp = send_email.call_args.args[1]
        wrong_otp = f"{(int(otp) + 1) % 1_000_000:06d}"

        token = self.csrf(self.client, "/forgot-password")
        invalid_response = self.client.post("/reset-password/verify", data={
            "csrf_token": token,
            "email": "reset-reader@example.test",
            "otp": wrong_otp,
        }, follow_redirects=True)
        self.assertIn(b"The reset code is invalid or expired.", invalid_response.data)
        with bookbridge.app.app_context():
            reset = bookbridge.get_db().execute(
                "SELECT attempts FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            ).fetchone()
            self.assertEqual(reset["attempts"], 1)

        token = self.csrf(self.client, "/forgot-password")
        verified_response = self.client.post("/reset-password/verify", data={
            "csrf_token": token,
            "email": "reset-reader@example.test",
            "otp": otp,
        })
        self.assertEqual(verified_response.status_code, 302)
        self.assertEqual(verified_response.headers["Location"], "/reset-password")
        self.assertNotIn(otp.encode(), verified_response.data)
        self.assertEqual(self.client.get("/reset-password").status_code, 200)

        replay_client = bookbridge.app.test_client()
        token = self.csrf(replay_client, "/forgot-password")
        replay_response = replay_client.post("/reset-password/verify", data={
            "csrf_token": token,
            "email": "reset-reader@example.test",
            "otp": otp,
        }, follow_redirects=True)
        self.assertIn(b"The reset code is invalid or expired.", replay_response.data)
        self.assertEqual(replay_client.get("/reset-password").status_code, 302)

        token = self.csrf(self.client, "/reset-password")
        mismatch_response = self.client.post("/reset-password", data={
            "csrf_token": token,
            "password": "new-password-456",
            "confirm_password": "different-password",
        })
        self.assertEqual(mismatch_response.status_code, 200)
        self.assertIn(b"Passwords do not match.", mismatch_response.data)
        self.assertEqual(self.client.get("/reset-password").status_code, 200)

        token = self.csrf(self.client, "/reset-password")
        changed_response = self.client.post("/reset-password", data={
            "csrf_token": token,
            "password": "new-password-456",
            "confirm_password": "new-password-456",
        })
        self.assertEqual(changed_response.status_code, 302)
        self.assertEqual(changed_response.headers["Location"], "/login")
        with bookbridge.app.app_context():
            user = bookbridge.get_db().execute(
                "SELECT password_hash FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            self.assertFalse(check_password_hash(user["password_hash"], "existing-password-123"))
            self.assertTrue(check_password_hash(user["password_hash"], "new-password-456"))
            self.assertIsNone(bookbridge.get_db().execute(
                "SELECT id FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            ).fetchone())

        token = self.csrf(self.client, "/login")
        login_response = self.client.post("/login", data={
            "csrf_token": token,
            "email": "reset-reader@example.test",
            "password": "new-password-456",
        })
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(login_response.headers["Location"], "/")

    def test_password_reset_expiration_and_attempt_limit(self):
        user_id = self.create_user("expired-reader@example.test")
        with patch.object(bookbridge, "send_password_reset_email") as send_email:
            self.request_reset_code(self.client, "expired-reader@example.test")
        expired_otp = send_email.call_args.args[1]
        with bookbridge.app.app_context():
            bookbridge.get_db().execute(
                "UPDATE password_reset_tokens SET expires_at = 0 WHERE user_id = ?", (user_id,)
            )
            bookbridge.get_db().commit()
        token = self.csrf(self.client, "/forgot-password")
        expired_response = self.client.post("/reset-password/verify", data={
            "csrf_token": token,
            "email": "expired-reader@example.test",
            "otp": expired_otp,
        }, follow_redirects=True)
        self.assertIn(b"The reset code is invalid or expired.", expired_response.data)
        with bookbridge.app.app_context():
            self.assertIsNone(bookbridge.get_db().execute(
                "SELECT id FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            ).fetchone())

        limited_user_id = self.create_user("limited-reader@example.test")
        with patch.object(bookbridge, "send_password_reset_email") as send_email:
            self.request_reset_code(self.client, "limited-reader@example.test")
        valid_otp = send_email.call_args.args[1]
        wrong_otp = f"{(int(valid_otp) + 1) % 1_000_000:06d}"
        for _ in range(bookbridge.PASSWORD_RESET_MAX_ATTEMPTS):
            token = self.csrf(self.client, "/forgot-password")
            self.client.post("/reset-password/verify", data={
                "csrf_token": token,
                "email": "limited-reader@example.test",
                "otp": wrong_otp,
            })
        with bookbridge.app.app_context():
            reset = bookbridge.get_db().execute(
                "SELECT attempts, otp_hash FROM password_reset_tokens WHERE user_id = ?",
                (limited_user_id,),
            ).fetchone()
            self.assertEqual(reset["attempts"], bookbridge.PASSWORD_RESET_MAX_ATTEMPTS)
            self.assertIsNone(reset["otp_hash"])
        token = self.csrf(self.client, "/forgot-password")
        locked_response = self.client.post("/reset-password/verify", data={
            "csrf_token": token,
            "email": "limited-reader@example.test",
            "otp": valid_otp,
        }, follow_redirects=True)
        self.assertIn(b"The reset code is invalid or expired.", locked_response.data)

    def test_password_reset_does_not_report_delivery_when_smtp_fails(self):
        self.create_user("mail-failure@example.test")
        with patch.object(bookbridge, "send_password_reset_email", side_effect=OSError("private smtp detail")):
            response = self.request_reset_code(self.client, "mail-failure@example.test")
        self.assertIn(bookbridge.PASSWORD_RESET_GENERIC_MESSAGE.encode(), response.data)
        self.assertNotIn(b"private smtp detail", response.data)
        with bookbridge.app.app_context():
            self.assertIsNone(bookbridge.get_db().execute(
                "SELECT id FROM password_reset_tokens"
            ).fetchone())

    def test_smtp_delivery_uses_tls_and_environment_credentials(self):
        with patch.dict(os.environ, {
            "SMTP_HOST": "smtp.example.test",
            "SMTP_PORT": "587",
            "SMTP_USERNAME": "sender@example.test",
            "SMTP_PASSWORD": "environment-only-app-password",
            "SMTP_FROM_EMAIL": "sender@example.test",
        }, clear=False), patch.object(bookbridge.smtplib, "SMTP") as smtp:
            mail_server = smtp.return_value.__enter__.return_value
            bookbridge.send_password_reset_email("reader@example.test", "123456")

        smtp.assert_called_once_with("smtp.example.test", 587, timeout=10)
        mail_server.starttls.assert_called_once()
        mail_server.login.assert_called_once_with("sender@example.test", "environment-only-app-password")
        sent_message = mail_server.send_message.call_args.args[0]
        self.assertEqual(sent_message["To"], "reader@example.test")
        self.assertIn("123456", sent_message.get_content())

    def test_public_pages_contact_feedback_and_admin_guard(self):
        for path in ("/", "/books", "/requests", "/low-cost", "/about", "/contact", "/help", "/login", "/signup"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        homepage = self.client.get("/")
        self.assertIsNone(homepage.location)
        for label in (b"Find a book to take home.", b"Browse Books", b"Donate a Book", b"Request a Book",
                      b"Exchange Books", b"Books Under \xe2\x82\xb9200", b"Log In", b"Register",
                      b"Books looking for a reader", b"Search by title, author or keyword"):
            self.assertIn(label, homepage.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        token = self.csrf(self.client, "/contact")
        response = self.client.post("/contact", data={
            "csrf_token": token,
            "name": "Visitor",
            "email": "visitor@example.test",
            "subject": "Project feedback",
            "message": "The site is easy to navigate.",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Thanks for your feedback", response.data)

        self.signup(self.client, "Regular Member", "member@example.test")
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(self.client.get("/admin/support-tickets").status_code, 403)
        self.assertEqual(self.client.get("/admin/books/1/edit").status_code, 403)
        profile_page = self.client.get("/profile")
        self.assertEqual(profile_page.status_code, 200)
        token = self.csrf(self.client, "/profile")
        updated_profile = self.client.post("/profile", data={
            "csrf_token": token,
            "name": "Updated Member",
            "email": "updated-member@example.test",
        }, follow_redirects=True)
        self.assertEqual(updated_profile.status_code, 200)
        self.assertIn(b"Updated Member", updated_profile.data)

    def test_homepage_discovery_is_available_to_visitors_and_all_logged_in_roles(self):
        credentials = (
            ("reader@example.test", "Reader-Password8", 0),
            ("admin@example.test", "Admin-Password8", 1),
        )
        clients = [("visitor", self.client)]
        for email, password, is_admin in credentials:
            with bookbridge.app.app_context():
                bookbridge.get_db().execute(
                    """INSERT INTO users (name, email, password_hash, is_admin, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (email.split("@")[0], email, generate_password_hash(password),
                     is_admin, bookbridge.utc_now()),
                )
                bookbridge.get_db().commit()
            client = bookbridge.app.test_client()
            token = self.csrf(client, "/login")
            login_response = client.post("/login", data={
                "csrf_token": token,
                "email": email,
                "password": password,
            })
            self.assertEqual(login_response.status_code, 302)
            self.assertEqual(login_response.location, "/")
            clients.append(("admin" if is_admin else "member", client))

        for role, client in clients:
            with self.subTest(role=role):
                homepage = client.get("/")
                self.assertEqual(homepage.status_code, 200)
                for label in (
                    b"Browse Books", b"Donate a Book", b"Request a Book",
                    b"Exchange Books", b"Books Under \xe2\x82\xb9200",
                    b"Search by title, author or keyword",
                    b'<option value="Good">Good</option>',
                ):
                    self.assertIn(label, homepage.data)
                self.assertIn(b'action="/books"', homepage.data)
                self.assertEqual(
                    client.get("/books?q=story&condition=Good&category=Fiction").status_code,
                    200,
                )
                self.assertEqual(client.get("/low-cost").status_code, 200)
                self.assertEqual(client.get("/requests").status_code, 200)
                if role == "member":
                    self.assertEqual(client.get("/admin").status_code, 403)

    def test_help_center_contains_guides_search_and_support_links(self):
        response = self.client.get("/help")
        self.assertEqual(response.status_code, 200)
        for label in (
            b"Browse books and contact an owner",
            b"Donate a book",
            b"Request a book",
            b"Exchange books",
            b"Under \xe2\x82\xb9200",
            b"About BookBridge",
            b"Dashboard and messages",
            b"Login",
            b"forgot password",
            b"Edit or remove my listing",
            b"Safety concern",
            b"data-help-search",
            b"Contact Customer Support",
        ):
            self.assertIn(label.lower(), response.data.lower())

    def test_support_ticket_privacy_replies_status_and_admin_permissions(self):
        owner = self.client
        self.signup(owner, "Ticket Owner", "ticket-owner@example.test")
        token = self.csrf(owner, "/donate")
        owner.post("/donate", data={
            "csrf_token": token,
            "title": "Ticket Related Book",
            "author": "A. Writer",
            "category": "Fiction",
            "condition": "Good",
            "location": "Pune",
        })
        with bookbridge.app.app_context():
            book_id = bookbridge.get_db().execute(
                "SELECT id FROM books WHERE title = ?", ("Ticket Related Book",)
            ).fetchone()["id"]

        stranger = bookbridge.app.test_client()
        self.signup(stranger, "Other Member", "other-member@example.test")
        self.assertEqual(bookbridge.app.test_client().get("/support").status_code, 302)

        token = self.csrf(owner, "/support")
        invalid_category = owner.post("/support", data={
            "csrf_token": token,
            "category": "Unexpected",
            "subject": "Private listing question",
            "description": "Details for support",
        })
        self.assertEqual(invalid_category.status_code, 200)
        self.assertIn(b"Choose a valid issue category.", invalid_category.data)
        with bookbridge.app.app_context():
            self.assertEqual(
                bookbridge.get_db().execute("SELECT COUNT(*) FROM support_tickets").fetchone()[0],
                0,
            )

        csrf_token = self.csrf(owner, "/support")
        missing_csrf = owner.post("/support", data={
            "category": "Book listing",
            "subject": "Private listing question",
            "description": "Details for support",
        })
        self.assertEqual(missing_csrf.status_code, 400)

        response = owner.post("/support", data={
            "csrf_token": csrf_token,
            "category": "Book listing",
            "book_id": str(book_id),
            "subject": "Private listing question",
            "description": "Please help with my listing.",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/support/tickets/1")
        self.assertIn(b"Ticket Related Book", owner.get(response.headers["Location"]).data)
        self.assertEqual(owner.get("/support/tickets").status_code, 200)
        self.assertEqual(stranger.get("/support/tickets").status_code, 200)
        self.assertNotIn(b"Private listing question", stranger.get("/support/tickets").data)
        self.assertEqual(stranger.get("/support/tickets/1").status_code, 404)
        self.assertEqual(bookbridge.app.test_client().get("/support/tickets/1").status_code, 302)
        self.assertEqual(stranger.get("/admin/support-tickets").status_code, 403)

        token = self.csrf(owner, "/support/tickets/1")
        response = owner.post("/support/tickets/1", data={
            "csrf_token": token,
            "body": "Here is one more detail.",
            "status": "Resolved",
        })
        self.assertEqual(response.status_code, 302)
        owner_ticket = owner.get("/support/tickets/1")
        self.assertIn(b"Here is one more detail.", owner_ticket.data)
        self.assertIn(b"Open", owner_ticket.data)
        self.assertEqual(stranger.get("/support/tickets/1").status_code, 404)

        with bookbridge.app.app_context():
            bookbridge.get_db().execute(
                "INSERT INTO users (name, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, 1, ?)",
                ("Support Admin", "support-admin@example.test",
                 generate_password_hash("test-support-admin-password"), bookbridge.utc_now()),
            )
            bookbridge.get_db().commit()
        admin = bookbridge.app.test_client()
        token = self.csrf(admin, "/login")
        response = admin.post("/login", data={
            "csrf_token": token,
            "email": "support-admin@example.test",
            "password": "test-support-admin-password",
        })
        self.assertEqual(response.status_code, 302)
        queue = admin.get("/admin/support-tickets")
        self.assertEqual(queue.status_code, 200)
        self.assertIn(b"Private listing question", queue.data)
        self.assertIn(b"ticket-owner@example.test", queue.data)
        token = self.csrf(admin, "/support/tickets/1")
        response = admin.post("/support/tickets/1", data={
            "csrf_token": token,
            "status": "In Progress",
            "body": "Support is reviewing your listing.",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn(b"In Progress", owner.get("/support/tickets/1").data)
        self.assertIn(b"Support is reviewing your listing.", owner.get("/support/tickets/1").data)

        token = self.csrf(admin, "/support/tickets/1")
        invalid_status = admin.post("/support/tickets/1", data={
            "csrf_token": token,
            "status": "Deleted",
            "body": "",
        })
        self.assertEqual(invalid_status.status_code, 200)
        self.assertIn(b"Choose a valid ticket status.", invalid_status.data)
        token = self.csrf(admin, "/support/tickets/1")
        closed = admin.post("/support/tickets/1", data={
            "csrf_token": token,
            "status": "Closed",
            "body": "Your issue has been closed.",
            "internal_note": "Reviewed the listing report and confirmed resolution.",
        })
        self.assertEqual(closed.status_code, 302)
        customer_view = owner.get("/support/tickets/1")
        self.assertIn(b"Closed", customer_view.data)
        self.assertIn(b"Your issue has been closed.", customer_view.data)
        self.assertNotIn(b"confirmed resolution", customer_view.data)
        admin_view = admin.get("/support/tickets/1")
        self.assertIn(b"confirmed resolution", admin_view.data)
        token = self.csrf(owner, "/support/tickets/1")
        closed_reply = owner.post("/support/tickets/1", data={
            "csrf_token": token, "body": "Another detail",
        }, follow_redirects=True)
        self.assertIn(b"This ticket is closed", closed_reply.data)
        self.assertNotIn(b"Another detail", admin.get("/support/tickets/1").data)

    def test_admin_dashboard_renders_for_configured_admin(self):
        with bookbridge.app.app_context():
            bookbridge.get_db().execute(
                "INSERT INTO users (name, email, password_hash, is_admin, created_at) VALUES (?, ?, ?, 1, ?)",
                ("Test Admin", bookbridge.INITIAL_ADMIN_EMAIL, generate_password_hash("test-admin-password"), bookbridge.utc_now()),
            )
            bookbridge.get_db().commit()
        admin_client = bookbridge.app.test_client()
        token = self.csrf(admin_client, "/login")
        response = admin_client.post("/login", data={
            "csrf_token": token,
            "email": bookbridge.INITIAL_ADMIN_EMAIL,
            "password": "test-admin-password",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        response = admin_client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Community overview", response.data)
        response = admin_client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        for label in (
            b"Manage All Books", b"Manage All Posts", b"Manage Donations",
            b"Manage Exchanges", b"Manage Book Sales", b"Manage Book Requests",
            b"Manage Users", b"Manage Support Requests", b"View Reports and Statistics",
        ):
            self.assertIn(label, response.data)
        self.assertIn(b"Reported Messages", response.data)
        self.assertIn(b"Manage Support Requests", admin_client.get("/help").data)
        self.assertEqual(admin_client.get("/admin/support-tickets").status_code, 200)

    def test_initial_admin_command_only_promotes_designated_existing_account(self):
        password_hash = generate_password_hash("unchanged-test-password")
        with bookbridge.app.app_context():
            database = bookbridge.get_db()
            database.execute(
                """INSERT INTO users (name, email, password_hash, created_at)
                   VALUES (?, ?, ?, ?)""",
                ("Designated Admin", bookbridge.INITIAL_ADMIN_EMAIL,
                 password_hash, bookbridge.utc_now()),
            )
            database.commit()
        runner = bookbridge.app.test_cli_runner()
        rejected = runner.invoke(
            args=["grant-initial-admin", "--confirm-email", "other@example.test"]
        )
        self.assertNotEqual(rejected.exit_code, 0)
        with bookbridge.app.app_context():
            user = bookbridge.get_db().execute(
                "SELECT is_admin, password_hash FROM users WHERE email = ?",
                (bookbridge.INITIAL_ADMIN_EMAIL,),
            ).fetchone()
            self.assertEqual(user["is_admin"], 0)
            self.assertEqual(user["password_hash"], password_hash)
        result = runner.invoke(
            args=[
                "grant-initial-admin",
                "--confirm-email",
                bookbridge.INITIAL_ADMIN_EMAIL,
            ]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        with bookbridge.app.app_context():
            user = bookbridge.get_db().execute(
                "SELECT is_admin, password_hash FROM users WHERE email = ?",
                (bookbridge.INITIAL_ADMIN_EMAIL,),
            ).fetchone()
            self.assertEqual(user["is_admin"], 1)
            self.assertEqual(user["password_hash"], password_hash)

    def test_message_reports_only_expose_reported_messages_and_allow_removal(self):
        owner = self.client
        self.signup(owner, "Private Book Owner", "private-owner@example.test")
        token = self.csrf(owner, "/donate")
        owner.post("/donate", data={
            "csrf_token": token, "title": "Private Conversation Book",
            "author": "Writer", "category": "Fiction", "condition": "Good",
            "location": "Pune",
        })
        with bookbridge.app.app_context():
            book_id = bookbridge.get_db().execute(
                "SELECT id FROM books WHERE title = 'Private Conversation Book'"
            ).fetchone()["id"]
        reader = bookbridge.app.test_client()
        self.signup(reader, "Private Book Reader", "private-reader@example.test")
        token = self.csrf(reader, f"/books/{book_id}")
        reader.post("/enquiries", data={
            "csrf_token": token, "book_id": str(book_id),
            "message": "I am interested in this book.",
        })
        with bookbridge.app.app_context():
            enquiry_id = bookbridge.get_db().execute(
                "SELECT id FROM enquiries WHERE book_id = ?", (book_id,)
            ).fetchone()["id"]
        token = self.csrf(owner, f"/messages/{enquiry_id}")
        owner.post(f"/messages/{enquiry_id}", data={
            "csrf_token": token, "body": "Please meet at the library.",
        })
        with bookbridge.app.app_context():
            message_id = bookbridge.get_db().execute(
                "SELECT id FROM messages WHERE enquiry_id = ?", (enquiry_id,)
            ).fetchone()["id"]
        stranger = bookbridge.app.test_client()
        self.assertEqual(stranger.get(f"/messages/{enquiry_id}").status_code, 302)
        token = self.csrf(reader, f"/messages/{enquiry_id}")
        response = reader.post(
            f"/messages/{enquiry_id}/report/{message_id}",
            data={"csrf_token": token, "reason": "Concerning meetup request"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"reported to BookBridge support", response.data)

        with bookbridge.app.app_context():
            bookbridge.get_db().execute(
                """INSERT INTO users (name, email, password_hash, is_admin, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                ("Report Moderator", "report-moderator@example.test",
                 generate_password_hash("report-moderator-password"), bookbridge.utc_now()),
            )
            bookbridge.get_db().commit()
        admin = bookbridge.app.test_client()
        token = self.csrf(admin, "/login")
        admin.post("/login", data={
            "csrf_token": token, "email": "report-moderator@example.test",
            "password": "report-moderator-password",
        })
        reports = admin.get("/admin/message-reports")
        self.assertEqual(reports.status_code, 200)
        self.assertIn(b"Please meet at the library.", reports.data)
        self.assertEqual(admin.get(f"/messages/{enquiry_id}").status_code, 404)
        token = self.csrf(admin, "/admin/message-reports")
        removed = admin.post("/admin/message-reports", data={
            "csrf_token": token, "report_id": "1", "action": "remove",
        })
        self.assertEqual(removed.status_code, 302)
        self.assertNotIn(b"Please meet at the library.", reader.get(f"/messages/{enquiry_id}").data)
        self.assertNotIn(b"Please meet at the library.", owner.get(f"/messages/{enquiry_id}").data)

    def test_admin_moderation_edits_listings_and_reports_database_statistics(self):
        owner = self.client
        self.signup(owner, "Listing Owner", "listing-owner@example.test")
        token = self.csrf(owner, "/donate")
        owner.post("/donate", data={
            "csrf_token": token, "title": "Moderated Book", "author": "Writer",
            "category": "Fiction", "condition": "Good", "location": "Pune",
        })
        token = self.csrf(owner, "/requests")
        owner.post("/requests", data={
            "csrf_token": token, "title": "Moderated Request", "author": "A Reader",
            "category": "Fiction", "location": "Pune", "message": "Looking for this book",
        })
        with bookbridge.app.app_context():
            database = bookbridge.get_db()
            database.execute(
                """INSERT INTO users (name, email, password_hash, is_admin, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                ("Moderation Admin", "moderator@example.test",
                 generate_password_hash("moderator-password"), bookbridge.utc_now()),
            )
            book_id = database.execute(
                "SELECT id FROM books WHERE title = 'Moderated Book'"
            ).fetchone()["id"]
            request_id = database.execute(
                "SELECT id FROM book_requests WHERE title = 'Moderated Request'"
            ).fetchone()["id"]
            database.commit()
        other_member = bookbridge.app.test_client()
        self.signup(other_member, "Other Listing Owner", "other-listing-owner@example.test")
        other_token = self.csrf(other_member, "/dashboard")
        self.assertEqual(other_member.post(
            f"/books/{book_id}/edit",
            data={"csrf_token": other_token, "title": "Not Your Book"},
        ).status_code, 404)
        self.assertEqual(other_member.get(f"/requests/{request_id}/edit").status_code, 404)
        admin = bookbridge.app.test_client()
        token = self.csrf(admin, "/login")
        admin.post("/login", data={
            "csrf_token": token, "email": "moderator@example.test",
            "password": "moderator-password",
        })
        response = admin.get("/admin")
        self.assertEqual(response.status_code, 200)
        for label in (b"Registered Users", b"Total Books", b"Donations",
                      b"Exchange Listings", b"Books for Sale", b"Book Requests",
                      b"Pending Support Tickets", b"Resolved Support Tickets"):
            self.assertIn(label, response.data)

        token = self.csrf(admin, "/admin")
        response = admin.post("/admin", data={
            "csrf_token": token, "action": "set_book_status",
            "status": "rejected", "record_id": str(book_id),
        })
        self.assertEqual(response.status_code, 302)
        self.assertNotIn(b"Moderated Book", owner.get("/books").data)
        token = self.csrf(owner, "/dashboard")
        self.assertEqual(owner.post(
            f"/books/{book_id}/toggle",
            data={"csrf_token": token},
        ).status_code, 403)

        token = self.csrf(admin, "/admin")
        admin.post("/admin", data={
            "csrf_token": token, "action": "set_book_status",
            "status": "approved", "record_id": str(book_id),
        })
        token = self.csrf(admin, f"/admin/books/{book_id}/edit")
        edited = admin.post(f"/admin/books/{book_id}/edit", data={
            "csrf_token": token, "title": "Corrected Book Title",
            "author": "Writer", "category": "Fiction", "condition": "Good",
            "location": "Pune", "description": "Updated by moderation",
            "image": (self.png_image(), "moderated-book.png"),
        })
        self.assertEqual(edited.status_code, 302)
        self.assertIn(b"Corrected Book Title", owner.get("/books").data)
        with bookbridge.app.app_context():
            image_filename = bookbridge.get_db().execute(
                "SELECT image_filename FROM books WHERE id = ?", (book_id,)
            ).fetchone()["image_filename"]
        self.assertIsNotNone(image_filename)
        self.assertTrue((self.upload_directory / image_filename).is_file())
        token = self.csrf(admin, f"/admin/books/{book_id}/edit")
        remove_image = admin.post(f"/admin/books/{book_id}/edit", data={
            "csrf_token": token, "title": "Corrected Book Title",
            "author": "Writer", "category": "Fiction", "condition": "Good",
            "location": "Pune", "description": "Updated by moderation",
            "remove_image": "1",
        })
        self.assertEqual(remove_image.status_code, 302)
        with bookbridge.app.app_context():
            self.assertIsNone(bookbridge.get_db().execute(
                "SELECT image_filename FROM books WHERE id = ?", (book_id,)
            ).fetchone()["image_filename"])
        self.assertFalse((self.upload_directory / image_filename).exists())

        token = self.csrf(admin, "/admin")
        admin.post("/admin", data={
            "csrf_token": token, "action": "delete_book", "record_id": str(book_id),
        })
        self.assertNotIn(b"Corrected Book Title", owner.get("/books").data)

        token = self.csrf(admin, "/admin")
        rejected_request = admin.post("/admin", data={
            "csrf_token": token, "action": "set_request_status",
            "status": "rejected", "record_id": str(request_id),
        })
        self.assertEqual(rejected_request.status_code, 302)
        self.assertNotIn(b"Moderated Request", owner.get("/requests").data)
        token = self.csrf(admin, f"/requests/{request_id}/edit")
        edited_request = admin.post(f"/requests/{request_id}/edit", data={
            "csrf_token": token, "title": "Corrected Request",
            "author": "A Reader", "category": "Fiction", "location": "Pune",
            "message": "Updated by admin",
        })
        self.assertEqual(edited_request.status_code, 302)
        token = self.csrf(admin, "/admin")
        admin.post("/admin", data={
            "csrf_token": token, "action": "set_request_status",
            "status": "approved", "record_id": str(request_id),
        })
        self.assertIn(b"Corrected Request", owner.get("/requests").data)
        token = self.csrf(admin, "/admin")
        admin.post("/admin", data={
            "csrf_token": token, "action": "delete_request", "record_id": str(request_id),
        })
        self.assertNotIn(b"Corrected Request", owner.get("/requests").data)

        with bookbridge.app.app_context():
            actions = bookbridge.get_db().execute(
                "SELECT action FROM admin_action_logs ORDER BY id"
            ).fetchall()
            action_names = {row["action"] for row in actions}
        self.assertIn("listing_deleted", action_names)
        self.assertIn("request_edited", action_names)
        self.assertIn("request_deleted", action_names)


if __name__ == "__main__":
    unittest.main()
