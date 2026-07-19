"""Shared route helpers: role-based access control on top of JWT."""

from __future__ import annotations

from functools import wraps

from flask_jwt_extended import get_jwt, verify_jwt_in_request
from flask_smorest import abort


def role_required(*roles: str):
    """Allow only JWTs whose `role` claim is one of `roles` (401 without a
    valid token, 403 with the wrong role)."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            role = get_jwt().get("role")
            if role not in roles:
                abort(
                    403,
                    message=f"Role '{role}' cannot access this resource "
                    f"(requires one of: {', '.join(roles)})",
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator
