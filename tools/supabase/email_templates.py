"""Cleave's Supabase Auth emails, built from one layout (DECISIONS.md §212).

    python3 tools/supabase/email_templates.py build
    python3 tools/supabase/email_templates.py preview <dir>
    SUPABASE_ACCESS_TOKEN=... python3 tools/supabase/email_templates.py push <project-ref>

``build`` writes one HTML file per template into
``infrastructure/supabase/email/built/`` -- the files pasted into the dashboard
(Authentication -> Emails), or sent by ``push``. Edit this script and
``infrastructure/supabase/email/layout.html``, never the built files.

``preview`` writes the same files with sample values in place of Supabase's
Go template variables, so they open in a browser.

``push`` sets every subject and body on a project through the Management API
(``PATCH /v1/projects/{ref}/config/auth``), with a personal access token from
supabase.com/dashboard/account/tokens. It replaces what the dashboard holds.

An email is a table layout with inline styles because that is all Outlook and
Gmail keep. The mark is a hosted PNG (``apps/web/public/email/``), not an SVG,
because Gmail drops SVG; it sits beside the word "cleave", so a client that
blocks images still names the sender.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EMAIL_DIR = ROOT / "infrastructure/supabase/email"

# The light theme's tokens (apps/web/src/index.css), written out: an email
# cannot read the stylesheet. layout.html holds the dark ones. MUTED is the
# app's --muted-foreground, which keeps 4.5:1 on the grey page as well as the card.
PRIMARY = "#106162"
FG = "#0a0a0a"
BODY = "#404040"
MUTED = "#696969"
BORDER = "#e5e5e5"
WELL = "#fafafa"
FONT = "Geist,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

# One radius rule: the card is 12px, everything inside it (button, wells) 8px.
INNER_RADIUS = "8px"

# Supabase's default for every emailed link and code (mailer_otp_exp, 3600s).
LINK_EXPIRY = "This link expires in 1 hour and can be used once."
CODE_EXPIRY = "This code expires in 1 hour and can be used once."


def title(text: str) -> str:
    return (
        f'<h1 class="cg-title cg-fg" style="margin:0 0 12px;font-size:24px;line-height:32px;'
        f'font-weight:600;letter-spacing:-0.4px;color:{FG};">{text}</h1>'
    )


def para(text: str) -> str:
    return (
        f'<p class="cg-body" style="margin:0 0 12px;font-size:15px;line-height:24px;'
        f'color:{BODY};">{text}</p>'
    )


def strong(text: str) -> str:
    return f'<strong class="cg-fg" style="font-weight:600;color:{FG};">{text}</strong>'


def small(text: str, bottom: int = 0) -> str:
    return (
        f'<p class="cg-muted" style="margin:0 0 {bottom}px;font-size:13px;line-height:20px;'
        f'color:{MUTED};">{text}</p>'
    )


def button(label: str) -> str:
    """A link drawn as a button that survives Outlook: the cell is the colour."""
    return f"""<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 12px;">
  <tr>
    <td class="cg-button" style="background:{PRIMARY};border-radius:{INNER_RADIUS};">
      <a href="{{{{ .ConfirmationURL }}}}" style="display:inline-block;padding:11px 20px;font-family:{FONT};font-size:14px;line-height:20px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:{INNER_RADIUS};">{label}</a>
    </td>
  </tr>
</table>
{small(LINK_EXPIRY, 28)}"""  # noqa: E501


def code() -> str:
    """A one-time code, set apart and spaced so it reads digit by digit."""
    # The left padding matches the letter spacing, which trails the last digit.
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 12px;">
  <tr>
    <td class="cg-well" align="center" style="background:{WELL};border:1px solid {BORDER};border-radius:{INNER_RADIUS};padding:18px 0 18px 8px;">
      <span class="cg-fg" style="font-family:{MONO};font-size:28px;line-height:36px;font-weight:500;letter-spacing:8px;color:{FG};">{{{{ .Token }}}}</span>
    </td>
  </tr>
</table>
{small(CODE_EXPIRY, 28)}"""  # noqa: E501


def change() -> str:
    """The address as it is and as it will be, the new one in the brand."""

    def row(label: str, colour: str, cls: str, value: str) -> str:
        return (
            f'<tr><td class="cg-muted" style="padding:3px 16px 3px 0;font-size:13px;'
            f'line-height:20px;color:{MUTED};white-space:nowrap;vertical-align:top;">{label}</td>'
            f'<td class="{cls}" style="padding:3px 0;font-size:14px;font-weight:500;'
            f'line-height:20px;color:{colour};word-break:break-all;">{value}</td></tr>'
        )

    rows = row("Current", FG, "cg-fg", "{{ .Email }}") + row(
        "New", PRIMARY, "cg-accent", "{{ .NewEmail }}"
    )
    return f"""<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:20px 0 0;">
  <tr>
    <td class="cg-well" style="background:{WELL};border:1px solid {BORDER};border-radius:{INNER_RADIUS};padding:12px 16px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0">{rows}</table>
    </td>
  </tr>
</table>"""  # noqa: E501


def closing(heading: str, text: str, *, link: bool = True) -> str:
    """Under a rule: what to do if the email was not expected, then the raw link.

    The link comes last and small, for a client that will not follow the
    button; above the rule there is only one thing to do.
    """
    rule = (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td class="cg-rule" style="border-top:1px solid {BORDER};font-size:0;'
        f'line-height:0;padding-top:24px;">&nbsp;</td></tr></table>'
    )
    out = rule + small(f"{strong(heading)} {text}", 16 if link else 0)
    if link:
        out += small("If the button doesn&rsquo;t work, paste this link into your browser:", 4)
        out += (
            f'<p class="cg-accent" style="margin:0;font-family:{MONO};font-size:12px;'
            f'line-height:18px;word-break:break-all;"><a href="{{{{ .ConfirmationURL }}}}" '
            f'style="color:{PRIMARY};text-decoration:none;">{{{{ .ConfirmationURL }}}}</a></p>'
        )
    return out


@dataclass(frozen=True)
class Template:
    """One Supabase email: its Management API key, subject, inbox preview and body."""

    key: str
    subject: str
    preheader: str
    reason: str
    content: str


TEMPLATES = [
    Template(
        key="confirmation",
        subject="Confirm your email for Cleave",
        preheader="Confirm your address to finish creating your Cleave account.",
        reason="You received this because {{ .Email }} was used to sign up for Cleave.",
        content=title("Confirm your email")
        + para(
            f"Confirm that {strong('{{ .Email }}')} is yours to finish creating your Cleave "
            "account. If a colleague invited you, the invitation is waiting once you sign in."
        )
        + button("Confirm email")
        + closing(
            "Didn&rsquo;t sign up?",
            "You can ignore this email. The address can&rsquo;t be used to sign in until it is "
            "confirmed.",
        ),
    ),
    Template(
        key="recovery",
        subject="Reset your Cleave password",
        preheader="Choose a new password for your Cleave account.",
        reason="You received this because a password reset was requested for {{ .Email }}.",
        content=title("Reset your password")
        + para(
            f"We received a request to reset the password for {strong('{{ .Email }}')}. "
            "Choose a new one to sign back in."
        )
        + button("Reset password")
        + closing(
            "Didn&rsquo;t request this?",
            "You can ignore this email. Your password won&rsquo;t change unless the link is used.",
        ),
    ),
    Template(
        key="magic_link",
        subject="Your Cleave sign-in link",
        preheader="Use this link to sign in to Cleave.",
        reason="You received this because a sign-in link was requested for {{ .Email }}.",
        content=title("Sign in to Cleave")
        + para(f"Use the button below to sign in as {strong('{{ .Email }}')}.")
        + button("Sign in")
        + closing(
            "Didn&rsquo;t request this?",
            "You can ignore this email. Nobody is signed in unless the link is used.",
        ),
    ),
    Template(
        key="email_change",
        subject="Confirm your new email for Cleave",
        preheader="Confirm the change to your Cleave sign-in address.",
        reason="You received this because an email change was requested for a Cleave account.",
        content=title("Confirm your new email")
        + para("Your Cleave sign-in address will change once you confirm.")
        + change()
        + button("Confirm change")
        + closing(
            "Didn&rsquo;t request this?",
            "Ignore this email and change your password. Your address stays the same unless "
            "the link is used.",
        ),
    ),
    Template(
        key="invite",
        subject="You've been invited to Cleave",
        preheader="Accept the invitation to create your Cleave account.",
        reason="You received this because {{ .Email }} was invited to Cleave.",
        content=title("You&rsquo;ve been invited to Cleave")
        + para(
            f"Accept the invitation to create an account as {strong('{{ .Email }}')}. Cleave "
            "maps the routes an attacker could take into your cloud, and the fix that closes "
            "the most."
        )
        + button("Accept invitation")
        + closing(
            "Not expecting this?",
            "You can ignore this email. No account is created unless you accept.",
        ),
    ),
    Template(
        key="reauthentication",
        subject="Your Cleave verification code",
        preheader="Enter this code in Cleave to confirm it&rsquo;s you.",
        reason="You received this because a verification code was requested for {{ .Email }}.",
        content=title("Your verification code")
        + para("Enter this code in Cleave to confirm it&rsquo;s you.")
        + code()
        + closing(
            "Didn&rsquo;t request this?",
            "Someone may know your password. Change it now, and never share this code.",
            link=False,
        ),
    ),
]

# What ``preview`` puts where Supabase would; the site is the local public dir.
SAMPLE = {
    "{{ .ConfirmationURL }}": (
        "https://example.supabase.co/auth/v1/verify?token=pkce_3f9a1c7e&type=signup"
        "&redirect_to=https://cleave.example"
    ),
    "{{ .SiteURL }}": (ROOT / "apps/web/public").as_uri(),
    "{{ .Email }}": "ada@contoso.com",
    "{{ .NewEmail }}": "ada.lovelace@contoso.com",
    "{{ .Token }}": "482913",
}


def render(template: Template) -> str:
    layout = (EMAIL_DIR / "layout.html").read_text()
    return (
        layout.replace("%%SUBJECT%%", template.subject)
        .replace("%%PREHEADER%%", template.preheader)
        .replace("%%REASON%%", template.reason)
        .replace("%%CONTENT%%", template.content)
    )


def build(out: Path, sample: dict[str, str] | None = None) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for template in TEMPLATES:
        html = render(template)
        for variable, value in (sample or {}).items():
            html = html.replace(variable, value)
        (out / f"{template.key}.html").write_text(html)
        print(out / f"{template.key}.html")


def push(project_ref: str) -> None:
    token = os.environ.get("SUPABASE_ACCESS_TOKEN")
    if not token:
        sys.exit("Set SUPABASE_ACCESS_TOKEN to a personal access token.")
    body: dict[str, str] = {}
    for template in TEMPLATES:
        body[f"mailer_subjects_{template.key}"] = template.subject
        body[f"mailer_templates_{template.key}_content"] = render(template)
    request = urllib.request.Request(
        f"https://api.supabase.com/v1/projects/{project_ref}/config/auth",
        data=json.dumps(body).encode(),
        method="PATCH",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request) as response:
        print(f"{response.status}: {len(TEMPLATES)} templates set on {project_ref}")


def main() -> None:
    command, *args = sys.argv[1:] or ["build"]
    if command == "build" and not args:
        build(EMAIL_DIR / "built")
    elif command == "preview" and len(args) == 1:
        build(Path(args[0]).resolve(), SAMPLE)
    elif command == "push" and len(args) == 1:
        push(args[0])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
