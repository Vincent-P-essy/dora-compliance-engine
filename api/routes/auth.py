"""Token issuance: POST /api/auth/token -> JWT with a role claim."""

from __future__ import annotations

from flask import current_app
from flask_jwt_extended import create_access_token
from flask_smorest import Blueprint, abort
from marshmallow import Schema, fields
from sqlalchemy import select
from werkzeug.security import check_password_hash

from engine.db import SessionLocal, User

blp = Blueprint("auth", __name__, url_prefix="/api/auth", description="Authentication")


class TokenRequestSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True, load_only=True)


class TokenResponseSchema(Schema):
    access_token = fields.String()
    role = fields.String()
    expires_in = fields.Integer()


@blp.route("/token", methods=["POST"])
@blp.arguments(TokenRequestSchema)
@blp.response(200, TokenResponseSchema)
def issue_token(args):
    """Exchange username/password for a JWT (roles: CISO, DevOps, Auditor)."""
    session = SessionLocal()
    user = session.scalars(select(User).where(User.username == args["username"])).first()
    if user is None or not check_password_hash(user.password_hash, args["password"]):
        abort(401, message="Invalid credentials")
    token = create_access_token(identity=user.username, additional_claims={"role": user.role})
    return {
        "access_token": token,
        "role": user.role,
        "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    }
