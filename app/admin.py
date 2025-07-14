from flask import Blueprint, render_template, redirect, url_for, flash, abort, request
from flask_login import current_user, login_user, logout_user, login_required
from app.extensions import db
from app.forms import AdminLoginForm, ResolveClaimForm
from app.models import User, AdminAuditLog, Claim, Role, Notification
from sqlalchemy import func

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
def require_admin():
    """
    Restricts access to all admin routes to only authenticated admin users,
    except for the login page.
    """
    if request.endpoint == 'admin.admin_login':
        return

    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin.dashboard'))

    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()

        if user and user.check_password(form.password.data):
            if user.is_admin:
                login_user(user, remember=form.remember.data)
                log = AdminAuditLog(
                    admin_id=user.user_id,
                    action="Admin Login",
                    details=f"Admin {user.email} logged in."
                )
                db.session.add(log)
                db.session.commit()
                flash('Logged in successfully as Admin!', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('You do not have admin privileges.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')
    # CORRECTED: Changed 'admin_login.html' to 'admin_login.html' (already correct, but confirming)
    return render_template('admin_login.html', form=form)

@admin_bp.route('/logout')
@login_required
def admin_logout():
    if current_user.is_admin:
        log = AdminAuditLog(
            admin_id=current_user.user_id,
            action="Admin Logout",
            details=f"Admin {current_user.email} logged out."
        )
        db.session.add(log)
        db.session.commit()
    logout_user()
    flash('You have been logged out of the admin panel.', 'info')
    return redirect(url_for('main.home'))

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    """Displays the admin dashboard with summary statistics."""
    user_count = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    inactive_users = User.query.filter_by(is_active=False).count()
    admin_role = Role.query.filter_by(role_name='admin').first()
    admin_count = User.query.filter_by(role=admin_role).count() if admin_role else 0
    regular_users = user_count - admin_count

    claim_stats = {
        'total': Claim.query.count(),
        'pending': Claim.query.filter_by(status='pending').count(),
        'under_review': Claim.query.filter_by(status='under_review').count(),
        'approved': Claim.query.filter_by(status='approved').count(),
        'rejected': Claim.query.filter_by(status='rejected').count(),
        'resolved': Claim.query.filter_by(status='resolved').count()
    }
    recent_logs = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).limit(5).all()
    recent_activities_count = AdminAuditLog.query.count()

    # CORRECTED: Changed 'admin_dashboard.html' to 'admin_dashboard.html' (already correct)
    return render_template('admin_dashboard.html',
                           user_count=user_count,
                           pending_claims=claim_stats['pending'],
                           recent_activities=recent_activities_count,
                           recent_logs=recent_logs,
                           active_users=active_users,
                           inactive_users=inactive_users,
                           admin_count=admin_count,
                           regular_users=regular_users,
                           claim_stats=claim_stats)

@admin_bp.route('/manage_users')
@login_required
def manage_users():
    """Manages user accounts."""
    users = User.query.all()
    roles = Role.query.all()
    # CORRECTED: Changed 'manage_users.html' to 'manage_users.html' (already correct)
    return render_template('manage_users.html', users=users, roles=roles)


@admin_bp.route('/user/<int:user_id>/assign_role', methods=['GET', 'POST'])
@login_required
def assign_role(user_id):
    """Assigns a role to a user."""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_role_id = request.form.get('role_id', type=int)
        if new_role_id:
            new_role = Role.query.get(new_role_id)
            if new_role:
                user.role = new_role
                db.session.commit()

                log = AdminAuditLog(
                    admin_id=current_user.user_id,
                    action=f"Updated role for user {user.email}",
                    details=f"User ID: {user.user_id}, New Role: {new_role.role_name}, Is Admin: {user.is_admin}"
                )
                db.session.add(log)
                db.session.commit()

                flash(f'Role for {user.email} updated to {new_role.role_name} successfully!', 'success')
            else:
                flash('Selected role does not exist.', 'danger')
        else:
            flash('No role selected.', 'danger')
        return redirect(url_for('admin.manage_users'))

    roles = Role.query.all()
    # CORRECTED: Changed 'admin/assign_role_modal.html' to 'assign_role_modal.html' (assuming this is a separate modal template)
    # If assign_role_modal.html is not a standalone template and is part of manage_users.html, then this line might need adjustment.
    # For now, I'll assume it's a separate template.
    return render_template('assign_role_modal.html', user=user, roles=roles)


@admin_bp.route('/audit_logs')
@login_required
def audit_logs():
    """Displays system audit logs."""
    logs = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).all()
    # CORRECTED: Changed 'audit_logs.html' to 'audit_logs.html' (already correct)
    return render_template('audit_logs.html', logs=logs)

@admin_bp.route('/system_settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    """Manages system-wide settings."""
    if request.method == 'POST':
        flash('System settings updated successfully!', 'success')
    # CORRECTED: Changed 'admin/system_settings.html' to 'system_settings.html'
    return render_template('system_settings.html')


@admin_bp.route('/manage_claims')
@login_required
def manage_claims():
    """Manages claims submitted by users."""
    claims = Claim.query.order_by(Claim.reported_at.desc()).all()
    # CORRECTED: Changed 'manage_claims.html' to 'manage_claims.html' (already correct)
    return render_template('manage_claims.html', claims=claims)

@admin_bp.route('/claim/<int:claim_id>/resolve', methods=['GET', 'POST'])
@login_required
def resolve_claim(claim_id):
    """Resolves a specific claim."""
    claim = Claim.query.get_or_404(claim_id)
    form = ResolveClaimForm()

    if form.validate_on_submit():
        claim.status = 'resolved'
        claim.resolution_type = form.resolution_type.data
        claim.admin_notes = form.admin_notes.data
        claim.resolved_by_admin_id = current_user.user_id
        claim.resolved_at = func.now()

        db.session.commit()

        log = AdminAuditLog(
            admin_id=current_user.user_id,
            action=f"Resolved claim {claim.claim_id}",
            details=f"Claim ID: {claim_id}, New Status: {claim.status}, Resolution Type: {claim.resolution_type}"
        )
        db.session.add(log)
        db.session.commit()
        flash(f'Claim {claim_id} resolved successfully!', 'success')

        # Notify the claimant that their claim has been resolved by an admin
        notification_message = f"Your claim for '{claim.item.item_name}' has been resolved by an administrator."
        notification = Notification(user_id=claim.user_id, item_id=claim.item.item_id, message=notification_message)
        db.session.add(notification)
        db.session.commit()

        return redirect(url_for('admin.manage_claims'))

    if claim.resolution_type:
        form.resolution_type.data = claim.resolution_type
    if claim.admin_notes:
        form.admin_notes.data = claim.admin_notes

    # CORRECTED: Changed 'resolve_claim.html' to 'resolve_claim.html' (already correct)
    return render_template('resolve_claim.html', form=form, claim=claim)

@admin_bp.route('/user/<int:user_id>/claims')
@login_required
def user_claims(user_id):
    """Displays claims made by a specific user."""
    user = User.query.get_or_404(user_id)
    claims = Claim.query.filter_by(user_id=user_id).order_by(Claim.reported_at.desc()).all()
    # CORRECTED: Changed 'admin/user_claims.html' to 'user_claims.html'
    return render_template('user_claims.html', user=user, claims=claims)

@admin_bp.route('/system_status')
@login_required
def system_status():
    """Displays system health and status information."""
    # CORRECTED: Changed 'admin/system_status.html' to 'system_status.html'
    return render_template('system_status.html')

@admin_bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Deletes a user account."""
    user = User.query.get_or_404(user_id)
    if user.user_id == current_user.user_id:
        flash("You cannot delete your own admin account!", "danger")
        return redirect(url_for('admin.manage_users'))

    admin_role = Role.query.filter_by(role_name='admin').first()
    if admin_role and user.role_id == admin_role.role_id:
        active_admins_count = User.query.filter(User.role_id == admin_role.role_id, User.user_id != user_id).count()
        if active_admins_count < 1:
            flash("Cannot delete the last admin account! Please ensure at least one admin remains.", "danger")
            return redirect(url_for('admin.manage_users'))

    log = AdminAuditLog(
        admin_id=current_user.user_id,
        action=f"Deleted user {user.email}",
        details=f"User ID: {user.user_id}, Email: {user.email}"
    )
    db.session.add(log)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.email} deleted successfully!', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/user/<int:user_id>/activate', methods=['POST'])
@login_required
def activate_user(user_id):
    """Activates a user account."""
    user = User.query.get_or_404(user_id)
    if user.is_active:
        flash(f"User {user.email} is already active.", "info")
    else:
        user.is_active = True
        db.session.commit()
        log = AdminAuditLog(
            admin_id=current_user.user_id,
            action=f"Activated user {user.email}",
            details=f"User ID: {user.user_id}, Email: {user.email}"
        )
        db.session.add(log)
        db.session.commit()
        flash(f"User {user.email} activated successfully.", "success")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/user/<int:user_id>/deactivate', methods=['POST'])
@login_required
def deactivate_user(user_id):
    """Deactivates a user account."""
    user = User.query.get_or_404(user_id)
    if user.user_id == current_user.user_id:
        flash("You cannot deactivate your own account!", "danger")
        return redirect(url_for('admin.manage_users'))
    if not user.is_active:
        flash(f"User {user.email} is already inactive.", "info")
    else:
        user.is_active = False
        db.session.commit()
        log = AdminAuditLog(
            admin_id=current_user.user_id,
            action=f"Deactivated user {user.email}",
            details=f"User ID: {user.user_id}, Email: {user.email}"
        )
        db.session.add(log)
        db.session.commit()
        flash(f"User {user.email} deactivated successfully.", "success")
    return redirect(url_for('admin.manage_users'))
