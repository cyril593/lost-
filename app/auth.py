# app/auth.py

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from app import db
from app.forms import LoginForm, RegistrationForm
from app.models import User, UserProfile, AdminProfile, Role

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        password_data = form.password.data.strip()
        name_data = form.name.data.strip()

        # DEBUGGING: Print plain-text password before hashing
        print(f"DEBUG (Register): Plain-text password received: '{password_data}'")

        existing_user = User.query.filter_by(email=email_data).first()
        if existing_user:
            flash('An account with this email already exists. Please login or use a different email.', 'danger')
            return render_template('auth/register.html', form=form)

        role_name = form.role.data
        role = Role.query.filter_by(role_name=role_name).first()

        if not role:
            flash('Invalid role selected.', 'danger')
            return render_template('auth/register.html', form=form)

        new_user = User(
            email=email_data,
            name=name_data,
            role=role
        )
        new_user.set_password(password_data) # This is where the hashing happens

        # DEBUGGING: Print hashed password after set_password call
        print(f"DEBUG (Register): Hashed password in new_user object before commit: '{new_user.password}'")


        db.session.add(new_user)
        
        try:
            db.session.flush() # To get user_id for profile creation

            if role_name == 'user':
                student_id_data = form.student_id.data.strip()
                if not student_id_data:
                    flash('Student ID is required for regular user registration.', 'danger')
                    db.session.rollback()
                    return render_template('auth/register.html', form=form)
                new_user_profile = UserProfile(user=new_user, student_id=student_id_data)
                db.session.add(new_user_profile)
            elif role_name == 'admin':
                new_admin_profile = AdminProfile(admin=new_user)
                db.session.add(new_admin_profile)

            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration. Please try again. ({e})', 'danger')
            current_app.logger.error(f"Registration error for email {email_data}: {e}")
            return render_template('auth/register.html', form=form)

    return render_template('auth/register.html', form=form)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        email_data = form.email.data.strip().lower()
        password_data = form.password.data.strip()

        # DEBUGGING: Print submitted email and plain-text password for login attempt
        print(f"DEBUG (Login): Attempting login for email: '{email_data}'")
        print(f"DEBUG (Login): Submitted plain-text password: '{password_data}'")

        user = User.query.filter_by(email=email_data).first()
        
        if user:
            # DEBUGGING: Print user found and stored hashed password
            print(f"DEBUG (Login): User found in DB: {user.email}")
            print(f"DEBUG (Login): Stored hashed password from DB: '{user.password}'")
            
            # DEBUGGING: Print result of the password check
            password_check_result = user.check_password(password_data)
            print(f"DEBUG (Login): Result of user.check_password(): {password_check_result}")

            if password_check_result:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Login successful!', 'success')
                return redirect(next_page or url_for('main.dashboard'))
            else:
                flash('Login Unsuccessful. Please check email and password', 'danger')
        else:
            print(f"DEBUG (Login): User not found in DB for email: '{email_data}'")
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('auth/login.html', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))