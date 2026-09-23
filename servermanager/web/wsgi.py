"""WSGI entry point (gunicorn servermanager.web.wsgi:app)."""
from . import create_app

app = create_app()
