from flask import Flask, current_app
from config import Config
from app.extensions import db, migrate, mail, login_manager
from flask_moment import Moment
import click
import getpass
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from app.cnn import ItemClassifier

moment = Moment()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    """Application factory function"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions early to make them available for CLI commands
    initialize_extensions(app)

    # Configure logging for the application
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        # Set log level to WARNING for production to reduce verbosity
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.WARNING) # Changed to WARNING for production
        app.logger.info('Lost and Found App startup')
    else:
        # For debug/testing, log to console as well
        logging.basicConfig(level=logging.INFO,
                            format='[%(asctime)s] %(levelname)s in %(name)s: %(message)s')
        app.logger.info('Lost and Found App startup (Debug Mode)')


    # Initialize the CNN classifier
    cnn_model_path = app.config.get('CNN_MODEL_PATH')
    if cnn_model_path:
        try:
            # Initialize the singleton instance and store it on the app context
            # The ItemClassifier constructor handles loading the model
            app.item_classifier = ItemClassifier(cnn_model_path)
            # Store the classifier in app.extensions for easy access in routes
            app.extensions['classifier'] = app.item_classifier

            if not app.item_classifier.is_loaded:
                # This error message is now more specific, as ItemClassifier itself logs loading issues
                app.logger.error("CNN classifier model could not be loaded. Image classification features will be unavailable.")
            else:
                app.logger.info("CNN classifier model initialized successfully.")
        except Exception as e:
            app.logger.error(f"Failed to initialize ItemClassifier instance: {e}. Image classification features will be unavailable.")
    else:
        app.logger.warning("CNN_MODEL_PATH not configured in config.py. Image classification features will be unavailable.")

    
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    from app.routes import main as main_bp
    app.register_blueprint(main_bp)
    from app.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')
    # Removed 'api_bp' as it's not defined as a separate blueprint in routes.py in the provided context.
    # If you intend to have a separate API blueprint, it needs to be defined as such.

    # Register CLI commands
    register_cli_commands(app)

    return app

def initialize_extensions(app):
    """Initializes Flask extensions with the app instance."""
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    login_manager.init_app(app)
    moment.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login"""
    from app.models import User
    return User.query.get(int(user_id))

def register_cli_commands(app):
    """Registers custom Flask CLI commands."""

    @app.cli.command("create_admin")
    @click.argument("email")
    @click.argument("password")
    def create_admin_command(email, password):
        """Creates a new admin user."""
        from app.models import User, Role
        from app.extensions import db # Import db here to avoid circular import issues with app context
        with app.app_context():
            admin_role = Role.query.filter_by(role_name='admin').first()
            if not admin_role:
                click.echo("Error: Admin role not found. Run 'flask seed_roles' first.")
                return

            # Check if user already exists
            if User.query.filter_by(email=email).first():
                click.echo(f"Error: User with email '{email}' already exists.")
                return

            user = User(
                email=email,
                name="Admin", # Default name for admin created via CLI
                role_id=admin_role.role_id,
                created_at=datetime.utcnow()
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            click.echo(f"Success: Admin user '{email}' created!")

    @app.cli.command("seed_roles")
    def seed_roles_command():
        """Seeds default roles and permissions in the database."""
        from app.models import Role, Permission
        from app.extensions import db # Import db here
        with app.app_context():
            # Ensure permissions are seeded first
            if not Permission.query.first():
                click.echo("Seeding permissions...")
                Permission.seed_permissions()
                db.session.commit() # Commit after seeding permissions
                click.echo("Permissions seeded.")
            else:
                click.echo("Permissions already exist. Skipping seeding.")

            # Then seed roles
            if not Role.query.first():
                click.echo("Seeding roles...")
                Role.seed_roles()
                db.session.commit() # Commit after seeding roles
                click.echo("Roles seeded.")
            else:
                click.echo("Roles already exist. Skipping seeding.")
           
            click.echo("Default admin user creation skipped for security. Use 'flask create_admin' to create an admin.")
