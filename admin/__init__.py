"""
SR-02: Privileged staff access (Workstream B).

Security controls:
- Person-linked staff accounts; generic or shared
  names are refused and each client certificate
  belongs to exactly one account

Local academic prototype.
"""

from .accounts import (
    STAFF_ROLES,
    StaffAccountError,
    create_staff_account,
    find_staff_account,
)
from .models import StaffAccount
