# Role-based access control matrix (SR-04)

Draft: staff role permissions are awaiting Workstream B review (SR-06).

Source of truth: `ROLE_PERMISSIONS` in `platform_security/rbac.py`.
`tests/test_rbac_skeleton.py` fails if this table and the code differ.

Deny by default: a role holds only the permissions marked ✓.
Unknown roles, a missing role and unknown permissions are always denied.

| Permission | voter | officer | delegate | auditor | administrator |
|---|:-:|:-:|:-:|:-:|:-:|
| `ballot.request_entitlement` | ✓ |  |  |  |  |
| `records.read_own` | ✓ |  |  |  |  |
| `records.update_own_address` | ✓ |  |  |  |  |
| `candidates.read` |  | ✓ |  |  |  |
| `roll.approve_bulk` |  | ✓ |  |  |  |
| `roll.propose_bulk` |  | ✓ |  |  |  |
| `candidates.approve_exclusion` |  |  | ✓ |  |  |
| `candidates.approve_finalise` |  |  | ✓ |  |  |
| `candidates.enter` |  |  | ✓ |  |  |
| `candidates.propose_exclusion` |  |  | ✓ |  |  |
| `candidates.propose_finalise` |  |  | ✓ |  |  |
| `audit.read` |  |  |  | ✓ |  |
| `audit.verify` |  |  |  | ✓ |  |
| `bulletin.publish` |  |  |  | ✓ |  |
| `tally.run` |  |  |  | ✓ |  |
| `config.read` |  |  |  |  | ✓ |
| `results.publish` |  |  |  |  | ✓ |
| `staff.manage` |  |  |  |  | ✓ |

The role is read from the server-side session only. A role sent in a request body, query string or header is ignored.

"Own record" checks (for example `records.read_own`) are enforced separately by SR-05 ownership checks in `records.py`.
Different-person approval for propose/approve pairs is enforced by SR-06 (Workstream B), not by this matrix.
