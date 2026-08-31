"""JustiKey HTTP application server.

Built entirely on Python's standard library http.server. Implements:
  - two-step login (password, then TOTP)
  - random server-side session tokens, HttpOnly + SameSite cookies
  - CSRF protection on state-changing requests
  - warrant/legal-authority authorization requests
  - independent second-person approval (with TOTP) — self-approval is
    technically prohibited, not just discouraged by policy
  - policy-checked, narrowly-scoped disclosure of protected LPR records
  - a hash-chained audit ledger for every sensitive action
  - an authenticated ingest endpoint for sensor/simulator observations
"""
import hmac
import json
import re
import sys
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import anchor, audit, config, crypto_utils, db, models, policy, templates, timeutil

SESSION_COOKIE = config.SESSION_COOKIE_NAME
PENDING_COOKIE = config.PENDING_COOKIE_NAME

ROLES = ("requester", "approver", "auditor")

# Field limits for sensor-supplied observation data.
MAX_PLATE_LEN = 16
MAX_FIELD_LEN = 128

# A fixed hash used to spend the same PBKDF2 work on a login attempt for an
# unknown username as for a known one. Without it, an unknown username
# returns immediately while a known one costs a full PBKDF2 derivation,
# which times the difference and turns the login form into a username oracle.
_DUMMY_SALT = "00" * 16
_DUMMY_HASH, _ = crypto_utils.hash_password("password-that-is-never-valid", _DUMMY_SALT)


class HttpError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Redirect(Exception):
    def __init__(self, location):
        super().__init__(location)
        self.location = location


ROUTES = []


def route(method, pattern):
    regex = re.compile("^" + pattern + "$")

    def deco(fn):
        ROUTES.append((method, regex, fn))
        return fn

    return deco


def build_set_cookie(name, value, max_age=None):
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if config.COOKIE_SECURE:
        parts.append("Secure")
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def clear_cookie(name):
    return f"{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"


class Handler(BaseHTTPRequestHandler):
    server_version = "JustiKey/0.1"
    # Every response sets Content-Length (redirects included), so connections
    # can safely be reused.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # -- dispatch -----------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        self.query = parse_qs(parsed.query)
        self.session_row = None
        self.pending_row = None
        self.current_user = None
        self._responded = False
        self.body = b""
        self.conn = None
        try:
            # Read the body before routing. A handler that rejects a request
            # early (an auth redirect, a role check) would otherwise leave the
            # body unread in the socket and desynchronize the next request on
            # a reused connection.
            if method == "POST" and not self._read_body():
                return
            self.conn = db.get_connection()
            self.current_user = self._load_user()
            for m, regex, fn in ROUTES:
                if m != method:
                    continue
                match = regex.match(path)
                if match:
                    try:
                        fn(self, **match.groupdict())
                    except Redirect as r:
                        self._redirect(r.location)
                    except HttpError as e:
                        self._send_html(
                            e.code,
                            templates.layout(str(e.code), "", user=self.current_user, error=e.message),
                        )
                    return
            self._send_html(
                404, templates.layout("Not Found", "", user=self.current_user, error="404 Not Found")
            )
        except Exception:
            # Log the detail server-side; show the client nothing but a
            # generic message, so an unexpected fault cannot leak internals.
            traceback.print_exc(file=sys.stderr)
            if not self._responded:
                self._send_html(500, templates.layout(
                    "Server error", "", user=None,
                    error="Internal server error. The incident has been logged."))
        finally:
            if self.conn is not None:
                self.conn.close()

    # -- request helpers ------------------------------------------------

    def _get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _load_user(self):
        token = self._get_cookie(SESSION_COOKIE)
        if not token:
            return None
        session = models.get_session(self.conn, token, kind="full")
        if not session:
            return None
        user = models.get_user_by_id(self.conn, session["user_id"])
        if user:
            self.session_row = session
        return user

    def _load_pending(self):
        token = self._get_cookie(PENDING_COOKIE)
        if not token:
            return None
        pending = models.get_session(self.conn, token, kind="pending")
        self.pending_row = pending
        return pending

    def _read_body(self):
        """Read the request body once, enforcing a size cap.

        Returns False (having already responded) if the request should not
        proceed.
        """
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            self._send_json(400, {"error": "invalid Content-Length"})
            return False
        if length > config.MAX_BODY_BYTES:
            self.close_connection = True
            self._send_json(413, {"error": "request body too large"})
            return False
        self.body = self.rfile.read(length) if length else b""
        return True

    def _parse_form(self):
        data = parse_qs(self.body.decode("utf-8", errors="replace"))
        return {k: v[0] for k, v in data.items()}

    def _parse_json(self):
        if not self.body:
            return {}
        return json.loads(self.body.decode("utf-8"))

    def _check_csrf(self, form, session_row=None):
        session_row = session_row or self.session_row
        if not session_row:
            raise HttpError(403, "Missing session; please log in again.")
        token = form.get("csrf_token", "")
        if not token or not hmac.compare_digest(token, session_row["csrf_token"]):
            raise HttpError(403, "Invalid or missing CSRF token.")

    def _require_login(self, roles=None):
        if not self.current_user:
            raise Redirect("/login")
        if roles and self.current_user["role"] not in roles:
            raise HttpError(403, "Your role does not permit this action.")
        return self.current_user

    # -- response helpers -------------------------------------------------

    def _begin_response(self, code, content_type, length, cookies):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        # Disclosed records must never be written to a browser or proxy cache.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        self.send_header("Pragma", "no-cache")
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self._responded = True

    def _send_html(self, code, html_str, cookies=None):
        body = html_str.encode("utf-8")
        self._begin_response(code, "text/html; charset=utf-8", len(body), cookies)
        self.wfile.write(body)

    def _redirect(self, location, cookies=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, private")
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self._responded = True

    def _send_json(self, code, obj, cookies=None):
        body = json.dumps(obj).encode("utf-8")
        self._begin_response(code, "application/json", len(body), cookies)
        self.wfile.write(body)

    def _page(self, title, body, error=None, flash=None):
        return templates.layout(title, body, user=self.current_user, error=error, flash=flash)


# ===========================================================================
# Home
# ===========================================================================

@route("GET", "/")
def home(h):
    raise Redirect("/dashboard" if h.current_user else "/login")


@route("GET", "/healthz")
def healthz(h):
    h._send_json(200, {"status": "ok"})


# ===========================================================================
# Authentication: password, then TOTP
# ===========================================================================

LOGIN_FORM = """
<div class="card" style="max-width:420px;margin:40px auto;">
<h2>Sign in</h2>
<form method="post" action="/login">
<label>Username</label>
<input type="text" name="username" autocomplete="username" required autofocus>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password" required>
<button type="submit">Continue</button>
</form>
<p class="hint">This is a laboratory prototype. Demo credentials were printed to the
server console on first startup. Second-factor codes can be generated with
<code>scripts/show_totp.py &lt;username&gt;</code>.</p>
</div>
"""


@route("GET", "/login")
def login_form(h):
    if h.current_user:
        raise Redirect("/dashboard")
    h._send_html(200, h._page("Sign in", LOGIN_FORM))


@route("POST", "/login")
def login_submit(h):
    if h.current_user:
        raise Redirect("/dashboard")
    form = h._parse_form()
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    user = models.get_user_by_username(h.conn, username)
    if user is None:
        # Spend the same PBKDF2 work as a real check so response time does
        # not reveal whether the username exists.
        crypto_utils.verify_password(password, _DUMMY_SALT, _DUMMY_HASH)
        ok = False
    else:
        ok = crypto_utils.verify_password(password, user["salt"], user["password_hash"])
    if not ok:
        audit.append_event(h.conn, "login_failed", username or "(blank)", {"reason": "bad_credentials"})
        h._send_html(200, h._page("Sign in", LOGIN_FORM, error="Invalid username or password."))
        return
    token = models.create_pending_session(h.conn, user["id"])
    h._redirect("/login/totp", cookies=[build_set_cookie(PENDING_COOKIE, token, config.PENDING_LOGIN_LIFETIME_SECONDS)])


TOTP_FORM = """
<div class="card" style="max-width:420px;margin:40px auto;">
<h2>Two-factor verification</h2>
<form method="post" action="/login/totp">
%s
<label>6-digit authenticator code</label>
<input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" required autofocus>
<button type="submit">Verify</button>
</form>
</div>
"""


def _totp_page(h, pending, error=None):
    body = TOTP_FORM % templates.csrf_field(pending["csrf_token"])
    return h._page("Two-factor verification", body, error=error)


@route("GET", "/login/totp")
def login_totp_form(h):
    pending = h._load_pending()
    if not pending:
        raise Redirect("/login")
    h._send_html(200, _totp_page(h, pending))


@route("POST", "/login/totp")
def login_totp_submit(h):
    pending = h._load_pending()
    if not pending:
        raise Redirect("/login")
    form = h._parse_form()
    h._check_csrf(form, session_row=pending)
    user = models.get_user_by_id(h.conn, pending["user_id"])
    code = form.get("code", "")
    if not user or not models.consume_totp(h.conn, user, code, "login"):
        audit.append_event(h.conn, "login_totp_failed", user["username"] if user else "(unknown)", {})
        h._send_html(200, _totp_page(h, pending, error="Invalid, expired, or already-used code."))
        return
    models.delete_session(h.conn, h._get_cookie(PENDING_COOKIE))
    full_token = models.create_full_session(h.conn, user["id"])
    audit.append_event(h.conn, "login_success", user["username"], {"role": user["role"]})
    h._redirect(
        "/dashboard",
        cookies=[
            clear_cookie(PENDING_COOKIE),
            build_set_cookie(SESSION_COOKIE, full_token, config.SESSION_LIFETIME_SECONDS),
        ],
    )


@route("POST", "/logout")
def logout(h):
    if h.current_user and h.session_row:
        form = h._parse_form()
        h._check_csrf(form)
        audit.append_event(h.conn, "logout", h.current_user["username"], {})
        models.delete_session(h.conn, h._get_cookie(SESSION_COOKIE))
    h._redirect("/login", cookies=[clear_cookie(SESSION_COOKIE)])


# ===========================================================================
# Dashboard
# ===========================================================================

@route("GET", "/dashboard")
def dashboard(h):
    user = h._require_login()
    total_events = models.count_events(h.conn)
    pending_auth = models.count_pending_authorizations(h.conn)
    active_auth = models.count_active_authorizations(h.conn)
    audit_entries = models.count_audit_entries(h.conn)

    role_note = {
        "requester": "You may create authorization requests and search protected records "
                     "once your requests are independently approved.",
        "approver": "You may independently review and approve or deny pending authorization "
                    "requests. You cannot approve your own requests.",
        "auditor": "You have read-only oversight access to all authorization requests and the "
                   "tamper-evident audit ledger.",
    }[user["role"]]

    body = f"""
<div class="card"><h2>System status</h2>
<div class="stats">
<div class="stat"><span class="n">{total_events}</span><span class="label">LPR observations ingested</span></div>
<div class="stat"><span class="n">{pending_auth}</span><span class="label">Pending authorization requests</span></div>
<div class="stat"><span class="n">{active_auth}</span><span class="label">Active (approved, unexpired) authorizations</span></div>
<div class="stat"><span class="n">{audit_entries}</span><span class="label">Audit ledger entries</span></div>
</div>
<p class="hint">Counts only. No plate-level history is shown here or anywhere without an
approved, scoped authorization.</p>
</div>
<div class="card"><h2>Signed in as {templates.escape(user["username"])} ({templates.escape(user["role"])})</h2>
<p class="muted">{role_note}</p>
</div>
"""
    h._send_html(200, h._page("Dashboard", body))


# ===========================================================================
# Authorizations (warrant / legal-authority requests)
# ===========================================================================

@route("GET", "/authorizations")
def authorizations_list(h):
    user = h._require_login()
    rows = models.list_authorizations(h.conn, user)
    show_requester = user["role"] != "requester"
    header = "<th>Requester</th>" if show_requester else ""
    trs = []
    for r in rows:
        eff = models.effective_status(r)
        req_cell = f"<td>{templates.escape(r['requester_username'])}</td>" if show_requester else ""
        trs.append(f"""<tr>
<td><a href="/authorizations/{r['id']}">#{r['id']}</a></td>
<td>{templates.escape(r['case_number'])}</td>
<td>{templates.escape(r['target_plate'])}</td>
{req_cell}
<td>{templates.status_badge(eff)}</td>
<td>{templates.escape(r['requested_at'][:19])}</td>
</tr>""")
    table = f"""<table><thead><tr>
<th>ID</th><th>Case</th><th>Target plate</th>{header}<th>Status</th><th>Requested</th>
</tr></thead><tbody>{''.join(trs) or '<tr><td colspan="6" class="muted">No authorization requests yet.</td></tr>'}</tbody></table>"""

    heading = "My requests" if user["role"] == "requester" else "Authorization requests"
    new_link = '<p><a href="/authorizations/new"><button>New request</button></a></p>' if user["role"] == "requester" else ""
    body = f'<div class="card"><h2>{heading}</h2>{new_link}{table}</div>'
    h._send_html(200, h._page(heading, body))


NEW_AUTH_FORM = """
<div class="card" style="max-width:560px;">
<h2>New access authorization</h2>
<p class="hint">This does not grant access by itself. A different, independently authenticated
approver must review and approve this request before any records can be disclosed.</p>
<form method="post" action="/authorizations/new">
%s
<label>Case number</label>
<input type="text" name="case_number" required placeholder="CASE-2026-001">
<label>Legal authority (warrant / court order reference)</label>
<input type="text" name="legal_authority" required placeholder="Warrant 2026-001">
<label>Investigative purpose</label>
<textarea name="purpose" rows="3" required></textarea>
<label>Target plate (exact match required at search time)</label>
<input type="text" name="target_plate" required placeholder="ABC123">
<label>Authorized window start (UTC)</label>
<input type="datetime-local" name="window_start" required>
<label>Authorized window end (UTC)</label>
<input type="datetime-local" name="window_end" required>
<button type="submit">Submit request</button>
</form>
</div>
"""


@route("GET", "/authorizations/new")
def new_authorization_form(h):
    user = h._require_login(roles=["requester"])
    body = NEW_AUTH_FORM % templates.csrf_field(h.session_row["csrf_token"])
    h._send_html(200, h._page("New request", body))


@route("POST", "/authorizations/new")
def new_authorization_submit(h):
    user = h._require_login(roles=["requester"])
    form = h._parse_form()
    h._check_csrf(form)
    required = ["case_number", "legal_authority", "purpose", "target_plate", "window_start", "window_end"]
    missing = [f for f in required if not (form.get(f) or "").strip()]
    if missing:
        body = NEW_AUTH_FORM % templates.csrf_field(h.session_row["csrf_token"])
        h._send_html(200, h._page("New request", body, error="All fields are required."))
        return
    try:
        window_start = models.parse_datetime_local_utc(form["window_start"])
        window_end = models.parse_datetime_local_utc(form["window_end"])
    except ValueError:
        body = NEW_AUTH_FORM % templates.csrf_field(h.session_row["csrf_token"])
        h._send_html(200, h._page("New request", body, error="Invalid date/time."))
        return
    if window_end <= window_start:
        body = NEW_AUTH_FORM % templates.csrf_field(h.session_row["csrf_token"])
        h._send_html(200, h._page("New request", body, error="Window end must be after window start."))
        return

    auth_id = models.create_authorization(
        h.conn,
        case_number=form["case_number"].strip(),
        legal_authority=form["legal_authority"].strip(),
        purpose=form["purpose"].strip(),
        target_plate=form["target_plate"].strip(),
        window_start=window_start,
        window_end=window_end,
        requested_by=user["id"],
    )
    audit.append_event(h.conn, "authorization_requested", user["username"], {
        "authorization_id": auth_id,
        "case_number": form["case_number"].strip(),
        "target_plate": form["target_plate"].strip().upper(),
    })
    h._redirect(f"/authorizations/{auth_id}")


def _authorization_detail_body(h, user, auth_row):
    eff = models.effective_status(auth_row)
    requester_name = auth_row["requester_username"]
    approver_name = auth_row["approver_username"]

    rows = f"""
<tr><th>Case number</th><td>{templates.escape(auth_row['case_number'])}</td></tr>
<tr><th>Legal authority</th><td>{templates.escape(auth_row['legal_authority'])}</td></tr>
<tr><th>Investigative purpose</th><td>{templates.escape(auth_row['purpose'])}</td></tr>
<tr><th>Target plate</th><td>{templates.escape(auth_row['target_plate'])}</td></tr>
<tr><th>Authorized window</th><td>{templates.escape(auth_row['window_start'])} &ndash; {templates.escape(auth_row['window_end'])}</td></tr>
<tr><th>Requested by</th><td>{templates.escape(requester_name)}</td></tr>
<tr><th>Requested at</th><td>{templates.escape(auth_row['requested_at'])}</td></tr>
<tr><th>Status</th><td>{templates.status_badge(eff)}</td></tr>
"""
    if approver_name:
        rows += f"<tr><th>Reviewed by</th><td>{templates.escape(approver_name)}</td></tr>"
    if auth_row["approved_at"]:
        rows += f"<tr><th>Reviewed at</th><td>{templates.escape(auth_row['approved_at'])}</td></tr>"
    if auth_row["status"] == "approved":
        rows += f"<tr><th>Approval expires</th><td>{templates.escape(auth_row['approval_expires_at'])}</td></tr>"
    if auth_row["denial_reason"]:
        rows += f"<tr><th>Denial reason</th><td>{templates.escape(auth_row['denial_reason'])}</td></tr>"

    actions = ""
    if user["role"] == "approver" and auth_row["status"] == "pending":
        if auth_row["requested_by"] == user["id"]:
            actions = '<p class="hint">You requested this authorization, so you cannot approve or deny it. A different approver must review it.</p>'
        else:
            actions = f"""
<div class="actions">
<a href="/authorizations/{auth_row['id']}/approve"><button>Approve (requires TOTP)</button></a>
<form method="post" action="/authorizations/{auth_row['id']}/deny" class="inline">
{templates.csrf_field(h.session_row['csrf_token'])}
<input type="text" name="reason" placeholder="Reason for denial" required style="display:inline-block;width:260px;">
<button type="submit" class="danger">Deny</button>
</form>
</div>
"""
    if user["role"] == "requester" and auth_row["requested_by"] == user["id"] and eff == "approved":
        actions += '<p><a href="/search"><button class="secondary">Go to authorized search</button></a></p>'

    return f'<div class="card"><h2>Authorization #{auth_row["id"]}</h2><table>{rows}</table>{actions}</div>'


@route("GET", r"/authorizations/(?P<auth_id>\d+)")
def authorization_detail(h, auth_id):
    user = h._require_login()
    auth_row = models.get_authorization_with_names(h.conn, int(auth_id))
    if not auth_row:
        raise HttpError(404, "Authorization not found.")
    if user["role"] == "requester" and auth_row["requested_by"] != user["id"]:
        raise HttpError(403, "You may only view your own authorization requests.")
    h._send_html(200, h._page(f"Authorization #{auth_id}", _authorization_detail_body(h, user, auth_row)))


@route("GET", r"/authorizations/(?P<auth_id>\d+)/approve")
def approve_form(h, auth_id):
    user = h._require_login(roles=["approver"])
    auth_row = models.get_authorization(h.conn, int(auth_id))
    if not auth_row:
        raise HttpError(404, "Authorization not found.")
    if auth_row["status"] != "pending":
        raise HttpError(400, "This authorization is no longer pending.")
    if auth_row["requested_by"] == user["id"]:
        raise HttpError(403, "You cannot approve your own request. A second, independent approver is required.")
    body = f"""
<div class="card" style="max-width:480px;">
<h2>Approve authorization #{auth_row['id']}</h2>
<p>Case <code>{templates.escape(auth_row['case_number'])}</code> &mdash; plate
<code>{templates.escape(auth_row['target_plate'])}</code></p>
<p class="hint">Confirm your identity with a current authenticator code before this request is approved.</p>
<form method="post" action="/authorizations/{auth_row['id']}/approve">
{templates.csrf_field(h.session_row['csrf_token'])}
<label>6-digit authenticator code</label>
<input type="text" name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" required autofocus>
<button type="submit">Approve</button>
</form>
</div>
"""
    h._send_html(200, h._page("Approve authorization", body))


@route("POST", r"/authorizations/(?P<auth_id>\d+)/approve")
def approve_submit(h, auth_id):
    user = h._require_login(roles=["approver"])
    form = h._parse_form()
    h._check_csrf(form)
    auth_row = models.get_authorization(h.conn, int(auth_id))
    if not auth_row:
        raise HttpError(404, "Authorization not found.")
    if auth_row["requested_by"] == user["id"]:
        audit.append_event(h.conn, "self_approval_denied", user["username"], {"authorization_id": int(auth_id)})
        raise HttpError(403, "You cannot approve your own request.")
    # A fresh code per approval: consuming it prevents one code from
    # rubber-stamping several requests inside the same 30-second step.
    if not models.consume_totp(h.conn, user, form.get("code", ""), "approval"):
        audit.append_event(h.conn, "approval_totp_failed", user["username"], {"authorization_id": int(auth_id)})
        raise HttpError(403, "Invalid, expired, or already-used authenticator code.")
    ok, reason = models.approve_authorization(h.conn, int(auth_id), user["id"])
    if not ok:
        audit.append_event(h.conn, "approval_denied", user["username"], {
            "authorization_id": int(auth_id), "reason": reason,
        })
        raise HttpError(400, f"Could not approve request: {reason}")
    audit.append_event(h.conn, "authorization_approved", user["username"], {
        "authorization_id": int(auth_id),
        "target_plate": auth_row["target_plate"],
    })
    h._redirect(f"/authorizations/{auth_id}")


@route("POST", r"/authorizations/(?P<auth_id>\d+)/deny")
def deny_submit(h, auth_id):
    user = h._require_login(roles=["approver"])
    form = h._parse_form()
    h._check_csrf(form)
    reason = (form.get("reason") or "").strip() or "No reason given"
    ok, err = models.deny_authorization(h.conn, int(auth_id), user["id"], reason)
    if not ok:
        raise HttpError(400, f"Could not deny request: {err}")
    audit.append_event(h.conn, "authorization_denied", user["username"], {
        "authorization_id": int(auth_id), "reason": reason,
    })
    h._redirect(f"/authorizations/{auth_id}")


# ===========================================================================
# Authorized search / disclosure
# ===========================================================================

@route("GET", "/search")
def search_form(h):
    user = h._require_login(roles=["requester"])
    active = models.list_active_authorizations_for_user(h.conn, user["id"])
    if not active:
        body = '<div class="card"><h2>Authorized search</h2>' \
               '<p class="muted">You have no approved, unexpired authorizations. ' \
               '<a href="/authorizations/new">Create a request</a> and have it independently approved first.</p></div>'
        h._send_html(200, h._page("Search", body))
        return
    options = "".join(
        f'<option value="{r["id"]}">#{r["id"]} &mdash; case {templates.escape(r["case_number"])} '
        f'&mdash; plate {templates.escape(r["target_plate"])} '
        f'(expires {templates.escape(r["approval_expires_at"][:19])})</option>'
        for r in active
    )
    body = f"""
<div class="card" style="max-width:560px;">
<h2>Authorized search</h2>
<p class="hint">You may only search the exact plate named in an approved authorization, and only
while that approval remains valid.</p>
<form method="post" action="/search">
{templates.csrf_field(h.session_row['csrf_token'])}
<label>Authorization</label>
<select name="authorization_id" required>{options}</select>
<label>Plate to search</label>
<input type="text" name="plate" required placeholder="ABC123">
<button type="submit">Search</button>
</form>
</div>
"""
    h._send_html(200, h._page("Search", body))


@route("POST", "/search")
def search_submit(h):
    user = h._require_login(roles=["requester"])
    form = h._parse_form()
    h._check_csrf(form)
    auth_id_raw = form.get("authorization_id", "")
    plate = form.get("plate", "")
    try:
        auth_id = int(auth_id_raw)
    except ValueError:
        raise HttpError(400, "Invalid authorization.")

    allowed, reason, events = policy.evaluate_disclosure(h.conn, auth_id, plate, user)

    if not allowed:
        audit.append_event(h.conn, "search_denied", user["username"], {
            "authorization_id": auth_id, "requested_plate": plate.strip().upper(), "reason": reason,
        })
        message = policy.DENIAL_MESSAGES.get(reason, "Access denied.")
        body = f'<div class="card"><h2>Search denied</h2><p>{templates.escape(message)}</p>' \
               f'<p><a href="/search">Back to search</a></p></div>'
        h._send_html(200, h._page("Search denied", body, error=message))
        return

    audit.append_event(h.conn, "disclosure", user["username"], {
        "authorization_id": auth_id, "target_plate": plate.strip().upper(), "record_count": len(events),
    })
    trs = "".join(f"""<tr>
<td>{templates.escape(e['captured_at'][:19])}</td>
<td>{templates.escape(e['plate'])}</td>
<td>{templates.escape(e['camera_id'])}</td>
<td>{e['confidence']:.2f}</td>
<td>{templates.escape(e['location'] or '')}</td>
<td>{templates.escape(e['source_id'] or '')}</td>
</tr>""" for e in events)
    table = f"""<table><thead><tr>
<th>Captured at (UTC)</th><th>Plate</th><th>Camera</th><th>Confidence</th><th>Location</th><th>Source</th>
</tr></thead><tbody>{trs or '<tr><td colspan="6" class="muted">No observations found in the authorized window.</td></tr>'}</tbody></table>"""
    body = f'<div class="card"><h2>Disclosed records ({len(events)})</h2>' \
           f'<p class="hint">This disclosure has been recorded in the audit ledger.</p>{table}</div>'
    h._send_html(200, h._page("Search results", body))


# ===========================================================================
# Audit oversight
# ===========================================================================

@route("GET", "/audit")
def audit_view(h):
    h._require_login(roles=["auditor"])
    rows = h.conn.execute(
        "SELECT seq, timestamp, event_type, actor, details, hash FROM audit_log ORDER BY seq DESC LIMIT 300"
    ).fetchall()
    trs = "".join(f"""<tr>
<td>{r['seq']}</td>
<td>{templates.escape(r['timestamp'][:19])}</td>
<td>{templates.escape(r['event_type'])}</td>
<td>{templates.escape(r['actor'])}</td>
<td><code style="font-size:11px;">{templates.escape(r['details'])}</code></td>
<td><code style="font-size:11px;">{templates.escape(r['hash'][:16])}&hellip;</code></td>
</tr>""" for r in rows)
    table = f"""<table><thead><tr>
<th>Seq</th><th>Timestamp</th><th>Event</th><th>Actor</th><th>Details</th><th>Hash</th>
</tr></thead><tbody>{trs or '<tr><td colspan="6" class="muted">No audit entries yet.</td></tr>'}</tbody></table>"""
    body = f"""
<div class="card"><h2>Audit ledger</h2>
<p class="hint">Most recent 300 entries. Each entry's hash incorporates the previous entry's hash,
forming a tamper-evident chain.</p>
<div class="actions">
<a href="/audit/verify"><button class="secondary">Verify integrity</button></a>
<form method="post" action="/audit/anchor" class="inline">
{templates.csrf_field(h.session_row['csrf_token'])}
<button type="submit" class="secondary">Anchor ledger head now</button>
</form>
</div>
{_anchor_status_html(h)}
{table}
</div>
"""
    h._send_html(200, h._page("Audit ledger", body))


def _anchor_status_html(h):
    """Show how current the published checkpoints are.

    Anchoring failures are deliberately non-fatal to audit writes, so the
    backlog has to be visible somewhere or a persistent failure would go
    unnoticed -- the exact silent-failure mode anchoring exists to remove.
    """
    store = anchor.AnchorStore.for_connection(h.conn, create_key=False)
    if store is None:
        return ('<p class="hint">Anchoring is not configured for this database, so '
                'truncation of the ledger tail would not be detectable.</p>')
    last = store.last()
    if last is None:
        return ('<p class="hint">No checkpoints published yet. Until one exists, deleting the '
                'most recent entries would leave a shorter chain that still verifies.</p>')
    behind = anchor.entries_since_last_anchor(h.conn, store)
    witness = f" Witness: <code>{templates.escape(config.WITNESS_URL)}</code>." if config.WITNESS_URL else \
              " No external witness configured."
    return (f'<p class="hint">Last checkpoint: anchor #{last["anchor_seq"]} at audit seq='
            f'{last["audit_seq"]} ({templates.escape(last["created_at"][:19])}); '
            f'{behind} entr{"y" if behind == 1 else "ies"} since.{witness}</p>')


@route("POST", "/audit/anchor")
def audit_anchor(h):
    user = h._require_login(roles=["auditor"])
    form = h._parse_form()
    h._check_csrf(form)
    store = anchor.AnchorStore.for_connection(h.conn)
    if store is None:
        raise HttpError(400, "Anchoring is not configured for this database.")
    record = anchor.create_anchor(h.conn, store)
    if record is None:
        raise Redirect("/audit")
    audit.append_event(h.conn, "audit_anchored", user["username"], {
        "anchor_seq": record["anchor_seq"], "audit_seq": record["audit_seq"],
    })
    h._redirect("/audit")


@route("GET", "/audit/verify")
def audit_verify(h):
    h._require_login(roles=["auditor"])

    chain_ok, info, reason = audit.verify_chain(h.conn)
    if chain_ok:
        chain_html = (f'<p class="success">Chain: OK &mdash; {info} entries verified, '
                      f'no entry has been modified or removed from the interior.</p>')
    else:
        chain_html = (f'<p class="error">Chain: FAILED at entry seq={info}: '
                      f'{templates.escape(reason)}</p>')

    store = anchor.AnchorStore.for_connection(h.conn, create_key=False)
    if store is None:
        anchor_html = ('<p class="error">Anchors: unavailable. Without published checkpoints, '
                       'truncation of the ledger tail cannot be detected.</p>')
        anchors_ok = False
    else:
        result = anchor.verify_anchors(h.conn, store)
        cls = "success" if result["ok"] else "error"
        label = "OK" if result["ok"] else f"FAILED ({result['status']})"
        anchor_html = (f'<p class="{cls}">Anchors: {label} &mdash; '
                       f'{templates.escape(result["message"])}</p>')
        anchors_ok = result["ok"]

    verdict = ('<p>The ledger is intact.</p>' if chain_ok and anchors_ok else
               '<p><strong>This ledger has failed verification and must be treated as '
               'unreliable pending investigation.</strong></p>')

    body = f"""<div class="card"><h2>Audit integrity verification</h2>
{chain_html}
{anchor_html}
{verdict}
<p class="hint">The chain proves no entry was altered. The anchors prove none were deleted from
the end &mdash; a check the chain cannot make on its own, since removing the newest entries leaves
a shorter chain that still verifies. Verify independently from the command line with
<code>python scripts/verify_audit.py --witness &lt;url&gt;</code>, which recomputes everything
directly from the stored files and can compare against a witness this application does not
control.</p>
<p><a href="/audit">Back to audit log</a></p></div>"""
    h._send_html(200, h._page("Audit verification", body))


# ===========================================================================
# Sensor / simulator ingest
# ===========================================================================

@route("POST", "/ingest")
def ingest(h):
    api_key = h.headers.get(config.INGEST_API_KEY_HEADER)
    if not models.verify_api_key(h.conn, api_key):
        audit.append_event(h.conn, "ingest_denied", "sensor:unknown", {"reason": "bad_api_key"})
        h._send_json(401, {"error": "invalid or missing API key"})
        return
    try:
        payload = h._parse_json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        h._send_json(400, {"error": "invalid JSON body"})
        return
    if not isinstance(payload, dict):
        h._send_json(400, {"error": "body must be a JSON object"})
        return

    plate = str(payload.get("plate", "")).strip().upper()
    if not plate:
        h._send_json(400, {"error": "plate is required"})
        return
    if len(plate) > MAX_PLATE_LEN:
        h._send_json(400, {"error": f"plate exceeds {MAX_PLATE_LEN} characters"})
        return

    camera_id = str(payload.get("camera_id", "unknown-camera")).strip()[:MAX_FIELD_LEN]
    source_id = str(payload.get("source_id", "unknown-source")).strip()[:MAX_FIELD_LEN]
    location = payload.get("location")
    if location is not None:
        location = str(location).strip()[:MAX_FIELD_LEN]

    # Normalize to canonical UTC now, at the trust boundary. Cameras from
    # different vendors emit different ISO-8601 flavors, and the stored value
    # is range-compared as text when an authorized search runs.
    raw_captured_at = payload.get("captured_at")
    try:
        captured_at = timeutil.parse(raw_captured_at) if raw_captured_at else timeutil.now_iso()
    except ValueError:
        h._send_json(400, {"error": "captured_at is not a valid ISO-8601 timestamp"})
        return

    try:
        confidence = float(payload.get("confidence", 0.9))
    except (TypeError, ValueError):
        confidence = 0.9
    if not 0.0 <= confidence <= 1.0:
        h._send_json(400, {"error": "confidence must be between 0.0 and 1.0"})
        return

    event_id = models.insert_event(h.conn, plate, captured_at, camera_id, confidence, location, source_id)
    audit.append_event(h.conn, "sensor_ingest", f"sensor:{source_id}", {
        "event_id": event_id, "camera_id": camera_id,
    })
    h._send_json(201, {"status": "accepted", "event_id": event_id})


# ===========================================================================
# Server entry point
# ===========================================================================

def run(host="127.0.0.1", port=8080):
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"JustiKey listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
