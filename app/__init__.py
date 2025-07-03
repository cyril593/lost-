from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config
import os

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# Login configuration
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Move this outside create_app (after db, login_manager are defined)
from app.models import User  # Only User needed here

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        return None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    # Import other models to register with SQLAlchemy
    with app.app_context():
        from app.models import (
            Role, Permission, AdminProfile,
            UserProfile, AdminAuditLog, Item, Notification
        )

    # Register blueprints
    from app.routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from app.auth import bp as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from app.admin import bp as admin_blueprint
    app.register_blueprint(admin_blueprint, url_prefix='/admin')

    # Optionally (re)set UPLOAD_FOLDER with absolute path
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')

    return app
