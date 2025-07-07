from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from app.extensions import db
from app.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm
from app.models import User, Role # Keep Role imported here

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        password_data = form.password.data.strip()
        name_data = form.name.data.strip()

        existing_user = User.query.filter_by(email=email_data).first()
        if existing_user:
            flash('An account with this email already exists. Please login or use a different email.', 'danger')
            return render_template('auth/register.html', form=form)

        role = Role.query.filter_by(role_name='general_user').first()
        if not role:
            # If the 'general_user' role is not found, it means the database wasn't seeded.
            # This should ideally not happen if 'flask seed_roles' has been run.
            flash('Application error: Default user role not found. Please contact support.', 'danger')
            current_app.logger.error("Error: 'general_user' role not found during registration. Run 'flask seed_roles'.")
            return render_template('auth/register.html', form=form)

        user = User(
            email=email_data,
            name=name_data,
            role_id=role.role_id,
            is_admin=False # New users are not admins by default
        )
        user.set_password(password_data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        password_data = form.password.data.strip()

        user = User.query.filter_by(email=email_data).first()

        if user:
            if not user.is_active:
                flash('Your account is inactive. Please contact an administrator.', 'danger')
            elif user.check_password(password_data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Login successful!', 'success')
                return redirect(next_page or url_for('main.dashboard'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('No account found with that email. Please register.', 'danger')

    return render_template('auth/login.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RequestResetForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        user = User.query.filter_by(email=email_data).first()
        if user:
            token = user.get_reset_token()
            reset_url = url_for('auth.reset_token', token=token, _external=True)
            print(f"\n--- Password Reset Link for {user.email} ---\n{reset_url}\n-------------------------------------------\n")
            flash('An email has been sent with instructions to reset your password. Check your console for the link.', 'info')
        else:
            flash('If an account with that email exists, an email has been sent with instructions to reset your password.', 'info')

        return redirect(url_for('auth.login'))

    return render_template('auth/reset_request.html', form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    user = User.verify_reset_token(token)

    if not user:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('auth.reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', form=form)