"""Minimal server-rendered HTML templating.

No third-party templating engine is used; every dynamic value passed
into markup goes through escape() to prevent XSS.
"""
import html as _html

# Held as a plain module constant rather than inlined into layout()'s
# f-string, so the stylesheet is not re-scanned and re-interpolated on
# every request (and so the CSS needs no brace-doubling).
STYLESHEET = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, system-ui, "Segoe UI", sans-serif; margin: 0;
  background: #0b1220; color: #e6edf3; }
header { background: #111827; padding: 14px 24px; display: flex; justify-content: space-between;
  align-items: center; border-bottom: 1px solid #22303c; }
header h1 { font-size: 18px; margin: 0; color: #7dd3fc; letter-spacing: 0.5px; }
header .tagline { font-size: 11px; color: #64748b; display: block; margin-top: 2px; }
nav { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
nav a { color: #9fd3f0; text-decoration: none; font-size: 14px; }
nav a:hover { text-decoration: underline; }
.user { color: #94a3b8; font-size: 13px; }
.rolebadge { background: #1e293b; padding: 1px 8px; border-radius: 10px; font-size: 11px; }
.linklike { background: none; border: none; color: #9fd3f0; cursor: pointer; font-size: 13px;
  text-decoration: underline; padding: 0; margin: 0; }
.inline { display: inline; }
main { padding: 28px 24px; max-width: 980px; margin: 0 auto; }
table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }
th, td { border: 1px solid #22303c; padding: 7px 10px; text-align: left; }
th { background: #111827; color: #9fb3c8; font-weight: 600; }
tr:nth-child(even) td { background: #0e1622; }
.card { background: #111827; border: 1px solid #22303c; border-radius: 10px; padding: 18px 20px;
  margin-bottom: 18px; }
.card h2 { margin-top: 0; font-size: 16px; color: #cbd5e1; }
.stats { display: flex; gap: 16px; flex-wrap: wrap; }
.stat { background: #111827; border: 1px solid #22303c; border-radius: 10px; padding: 16px 20px;
  min-width: 160px; }
.stat .n { font-size: 30px; font-weight: 700; color: #7dd3fc; display: block; }
.stat .label { font-size: 12px; color: #94a3b8; }
label { display: block; margin-top: 12px; font-size: 13px; color: #9fb3c8; }
input, select, textarea { width: 100%; padding: 9px; margin-top: 4px; background: #0b1220;
  border: 1px solid #2a3b4a; color: #e6edf3; border-radius: 6px; font-size: 14px; font-family: inherit; }
input:focus, select:focus, textarea:focus { outline: 1px solid #2563eb; }
button { margin-top: 16px; padding: 9px 18px; background: #2563eb; color: white; border: none;
  border-radius: 6px; cursor: pointer; font-size: 14px; }
button:hover { background: #1d4ed8; }
button.secondary { background: #374151; }
button.secondary:hover { background: #4b5563; }
button.danger { background: #b91c1c; }
button.danger:hover { background: #991b1b; }
.flash, .error, .success { padding: 11px 14px; border-radius: 8px; margin-bottom: 18px; font-size: 14px; }
.error { background: #3f1414; color: #fecaca; border: 1px solid #7f1d1d; }
.success { background: #0f2e1c; color: #bbf7d0; border: 1px solid #14532d; }
.badge { padding: 2px 10px; border-radius: 10px; font-size: 12px; display: inline-block; }
.badge.pending { background: #78350f; color: #fde68a; }
.badge.approved { background: #14532d; color: #bbf7d0; }
.badge.denied { background: #7f1d1d; color: #fecaca; }
.badge.expired { background: #374151; color: #d1d5db; }
code { background: #0b1220; padding: 2px 6px; border-radius: 4px; border: 1px solid #22303c; }
.hint { font-size: 12px; color: #64748b; margin-top: 4px; }
.muted { color: #64748b; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
"""

TAGLINE = ("Collect the event. Protect the identity. "
           "Require the authority. Record the access.")


def escape(value):
    return _html.escape("" if value is None else str(value), quote=True)


def _nav_for(user):
    """Build the navigation and identity block for the signed-in user."""
    if not user:
        return '<a href="/login">Login</a>', ""

    links = ['<a href="/dashboard">Dashboard</a>']
    if user["role"] == "requester":
        links += ['<a href="/authorizations">My Requests</a>',
                  '<a href="/authorizations/new">New Request</a>',
                  '<a href="/search">Search</a>']
    elif user["role"] == "approver":
        links += ['<a href="/authorizations">Approvals</a>']
    elif user["role"] == "auditor":
        links += ['<a href="/authorizations">All Requests</a>',
                  '<a href="/audit">Audit Log</a>']

    identity = (
        f'<span class="user">{escape(user["username"])} '
        f'<span class="rolebadge">{escape(user["role"])}</span></span>'
        '<form method="post" action="/logout" class="inline">'
        '<button type="submit" class="linklike">Logout</button></form>'
    )
    return " ".join(links), identity


def layout(title, body, user=None, flash=None, error=None):
    nav_html, user_html = _nav_for(user)

    if error:
        banner = f'<div class="error">{escape(error)}</div>'
    elif flash:
        banner = f'<div class="success">{escape(flash)}</div>'
    else:
        banner = ""

    return (
        '<!doctype html>\n<html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<title>{escape(title)} - JustiKey</title>\n'
        f'<style>{STYLESHEET}</style></head>\n<body>\n<header>\n'
        f'  <div><h1>JustiKey</h1><span class="tagline">{TAGLINE}</span></div>\n'
        f'  <nav>{nav_html}{user_html}</nav>\n</header>\n'
        f'<main>{banner}{body}</main>\n</body></html>'
    )


def csrf_field(csrf_token):
    return f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'


def status_badge(status):
    return f'<span class="badge {escape(status)}">{escape(status)}</span>'
