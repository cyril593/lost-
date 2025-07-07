from flask import Flask, current_app
from config import Config
from app.extensions import db, migrate, mail, login_manager
from flask_moment import Moment
import click
import getpass

# Initialize Flask-Moment extension
moment = Moment()

# Configure login manager settings
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    """Application factory function"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize logging
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler('app.log', maxBytes=10240)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

    # Initialize extensions
    initialize_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Add CLI commands
    add_cli_commands(app)
    
    return app

def initialize_extensions(app):
    """Initialize Flask extensions"""
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    login_manager.init_app(app)
    moment.init_app(app)
    
    # Initialize CNN classifier placeholder
    app.extensions['classifier'] = None

def register_blueprints(app):
    """Register all Flask blueprints"""
    from app.routes import main as main_bp
    from app.auth import bp as auth_bp
    from app.admin import admin_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')

def add_cli_commands(app):
    """Add Flask CLI commands"""

    @app.cli.command("create_admin")
    @click.argument("email")
    @click.argument("name")
    def create_admin(email, name):
        """Creates an admin user."""
        from app.models import User, Role
        from app.extensions import db
        
        password = getpass.getpass("Enter password: ")
        password2 = getpass.getpass("Repeat password: ")
        if password != password2:
            click.echo("Error: Passwords don't match!")
            return

        admin_role = Role.query.filter_by(role_name='admin').first()
        if not admin_role:
            click.echo("Error: 'admin' role not found. Run 'flask seed_roles' first.")
            return

        if User.query.filter_by(email=email).first():
            click.echo("Error: User with that email already exists.")
            return

        user = User(
            email=email.strip().lower(),
            name=name.strip(),
            role_id=admin_role.role_id,
            is_admin=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Success: Admin user '{email}' created!")

    @app.cli.command("seed_roles")
    def seed_roles():
        """Seed default roles in database"""
        from app.models import Role
        Role.seed_roles()
        click.echo("Success: Default roles seeded!")

@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login"""
    from app.models import User
    return User.query.get(int(user_id))

def get_item_classifier():
    """Get the CNN classifier instance with lazy loading"""
    if 'classifier' not in current_app.extensions or current_app.extensions['classifier'] is None:
        from app.cnn import ItemClassifier
        model_path = current_app.config.get('MODEL_PATH', 'app/static/model/item_classifier.pt') 
        current_app.extensions['classifier'] = ItemClassifier(model_path)
        
    return current_app.extensions['classifier']