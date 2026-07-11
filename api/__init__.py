"""Blueprint bundle for edo-plugin routes."""
from flask import Blueprint

from .admin import admin_bp
from .user import user_bp

edo_bp = Blueprint("edo", __name__, template_folder="../templates")

# Nested prefixes to make ACL policy easy to reason about.
edo_bp.register_blueprint(admin_bp, url_prefix="/admin")
edo_bp.register_blueprint(user_bp, url_prefix="")
