from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from app.extensions import db, mail
from app.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm
from app.models import User, Role
from flask_mail import Message

bp = Blueprint('auth', __name__)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender=current_app.config.get('MAIL_USERNAME', 'noreply@demo.com'), # Use .get() with a default
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('auth.reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
        current_app.logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send password reset email to {user.email}: {e}")
        flash('Failed to send password reset email. Please try again later.', 'danger')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        password_data = form.password.data.strip()
        name_data = form.name.data.strip()
        student_id_data = form.student_id.data.strip() if form.student_id.data else None

        existing_user = User.query.filter_by(email=email_data).first()
        if existing_user:
            flash('An account with this email already exists. Please login or use a different email.', 'danger')
            # CORRECTED: Changed 'auth/register.html' to 'register.html'
            return render_template('register.html', form=form)

        if student_id_data:
            existing_student_id_user = User.query.filter_by(student_id=student_id_data).first()
            if existing_student_id_user:
                flash('A user with this Student ID already exists. Please use a different one or leave it blank.', 'danger')
                # CORRECTED: Changed 'auth/register.html' to 'register.html'
                return render_template('register.html', form=form)


        role = Role.query.filter_by(role_name='general_user').first()
        if not role:
            flash('Application error: Default user role not found. Please contact support.', 'danger')
            current_app.logger.error("Error: 'general_user' role not found during registration. Run 'flask seed_roles'.")
            # CORRECTED: Changed 'auth/register.html' to 'register.html'
            return render_template('register.html', form=form)

        user = User(
            email=email_data,
            name=name_data,
            student_id=student_id_data,
            role_id=role.role_id,
        )
        user.set_password(password_data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    # CORRECTED: Changed 'auth/register.html' to 'register.html'
    return render_template('register.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        else:
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
                if user.is_admin:
                    return redirect(next_page or url_for('admin.dashboard'))
                else:
                    return redirect(next_page or url_for('main.dashboard'))
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('No account found with that email. Please register.', 'danger')

    # CORRECTED: Changed 'auth/login.html' to 'login.html'
    return render_template('login.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@bp.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('main.dashboard'))

    form = RequestResetForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        user = User.query.filter_by(email=email_data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('If an account with that email exists, an email has been sent with instructions to reset your password.', 'info')

        return redirect(url_for('auth.login'))

    # CORRECTED: Changed 'auth/reset_request.html' to 'reset_request.html'
    return render_template('reset_request.html', form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin.dashboard'))
        else:
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

    
    return render_template('reset_token.html', form=form)
