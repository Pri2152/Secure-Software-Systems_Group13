
"""
SR-04: Endpoint inventory for deny-by-default access control.

Security controls:
- Every registered Flask route must be explicitly
  public or protected, so a new unprotected route
  fails the build
- Protected means an SR-04 require_permission check
  or Workstream A's SR-16 require_active_session
- Markers must be exact (True / a permission name),
  so a stray truthy attribute does not count
- Public endpoints that no longer exist are reported,
  so the public list cannot silently grow stale

Local academic prototype.
"""


def is_protected_view(view_function):
    """
    Return True when the view carries an access
    control marker set by a trusted decorator.
    """

    permission = getattr(
        view_function, "required_permission", None
    )

    if isinstance(permission, str) and permission:
        return True

    return getattr(
        view_function, "requires_active_session", None
    ) is True


def find_unprotected_routes(app, public_endpoints):
    """
    Return every URL rule that is neither listed
    as public nor protected, sorted by path.
    """

    public = frozenset(public_endpoints)

    unprotected = [
        rule
        for rule in app.url_map.iter_rules()
        if rule.endpoint not in public
        and not is_protected_view(
            app.view_functions.get(rule.endpoint)
        )
    ]

    return sorted(
        unprotected,
        key=lambda rule: (rule.rule, rule.endpoint)
    )


def find_unknown_public_endpoints(app, public_endpoints):
    """
    Return listed public endpoints that the app
    does not register.
    """

    registered = {
        rule.endpoint
        for rule in app.url_map.iter_rules()
    }

    return sorted(set(public_endpoints) - registered)
