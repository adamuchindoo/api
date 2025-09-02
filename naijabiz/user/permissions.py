# user/permissions.py
from ninja import HttpError
from typing import Callable

def is_authenticated(request) -> bool:
    if not request.user.is_authenticated:
        raise HttpError(401, "Authentication required")
    return True

def allow_roles(*allowed_roles: str) -> Callable:
    def check(request):
        if not request.user.is_authenticated:
            raise HttpError(401, "Unauthorized")
        if request.user.role not in allowed_roles:
            raise HttpError(403, "Insufficient permissions")
        return True
    return check