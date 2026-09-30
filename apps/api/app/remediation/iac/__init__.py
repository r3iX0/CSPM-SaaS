"""Fix-as-Code: a rule's fix written into the customer's own infrastructure code
(DECISIONS.md §184)."""

from app.remediation.iac.terraform import (
    Change,
    Decline,
    Declined,
    Edit,
    Patched,
    edit_terraform,
)

__all__ = ["Change", "Decline", "Declined", "Edit", "Patched", "edit_terraform"]
