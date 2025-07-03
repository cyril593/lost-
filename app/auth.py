from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from app import db
from app.forms import LoginForm, RegistrationForm
from app.models import User, UserProfile, AdminProfile, Role

bp = Blueprint('auth', __name__)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Find or create role
        role = Role.query.filter_by(role_name=form.role.data).first()
        if not role:
            role = Role(role_name=form.role.data, is_admin=(form.role.data == 'admin'))
            db.session.add(role)
            db.session.flush()  # Assigns role_id without committing

        # Create user
        user = User(
            email=form.email.data,
            name=form.name.data,
            role_id=role.role_id
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()  # Assigns user_id without committing

        # Create appropriate profile
        if form.role.data == 'user':
            if not form.student_id.data:
                flash('Student ID is required for regular users.', 'danger')
                return render_template('auth/register.html', form=form)
            profile = UserProfile(user_id=user.user_id, student_id=form.student_id.data)
            db.session.add(profile)
        elif form.role.data == 'admin':
            admin_profile = AdminProfile(admin_id=user.user_id)
            db.session.add(admin_profile)

        # Final commit
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))
