"""Email + domain-allowlist rules for self-service signup.

Signup is open to any email by default. Admins can enable one or more allowed
email domains; as soon as at least one is enabled, only emails on that allowlist
may register and every other domain is blocked.
"""
import re

from sqlalchemy.orm import Session

from backend.database import SignupDomain

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# A domain label is 1-63 chars of alphanumerics/hyphens (not starting/ending with
# a hyphen), with at least two dot-separated labels and an alphabetic TLD.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email.strip()))


def email_domain(email: str) -> str:
    """Returns the lowercased domain part of an email address."""
    return email.strip().rsplit("@", 1)[-1].lower()


def normalize_domain(domain: str) -> str:
    """Normalizes user-entered domains: lowercase, trimmed, leading '@' removed."""
    return domain.strip().lower().lstrip("@")


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def enabled_domains(db: Session) -> list[str]:
    rows = (
        db.query(SignupDomain)
        .filter(SignupDomain.enabled.is_(True))
        .order_by(SignupDomain.domain.asc())
        .all()
    )
    return [r.domain for r in rows]


def is_email_allowed(db: Session, email: str) -> bool:
    """True if the email may register. When no domains are enabled the allowlist
    is inactive and every email is allowed."""
    active = enabled_domains(db)
    if not active:
        return True
    return email_domain(email) in set(active)
