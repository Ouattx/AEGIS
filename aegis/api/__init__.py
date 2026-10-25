"""AEGIS API: FastAPI application (OIDC/RBAC, multi-tenant) over the composition root.

- :func:`create_app` - application factory (``aegis.api.app``)
- :class:`Settings` - environment-driven configuration (``aegis.api.settings``)
"""
from aegis.api.settings import Settings, SettingsError


def create_app(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Lazy wrapper around :func:`aegis.api.app.create_app` (keeps ``import aegis.api`` light)."""
    from aegis.api.app import create_app as _create_app
    return _create_app(*args, **kwargs)


__all__ = ["Settings", "SettingsError", "create_app"]
