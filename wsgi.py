"""WSGI entry point — used by gunicorn (Docker) and `flask --app wsgi`."""

from api.app import create_app

app = create_app()
