from flask import Blueprint, render_template, redirect, url_for, flash, abort, request
from flask_login import current_user, login_user, logout_user, login_required
from app.extensions import db
from app.forms import AdminLoginForm, ResolveClaimForm
from app.models import User, AdminAuditLog, Claim, Role # Import Role to query for role names
from sqlalchemy import func # Import func for database functions like now()

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
def require_admin():
    """
    Restricts access to all admin routes to only authenticated admin users,
    except for the login page.
    """
    # Skip admin check for the login route
    if request.endpoint == 'admin.admin_login':
        return
        
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403) # Forbidden for non-admin or unauthenticated users

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin.dashboard'))

    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.strip().lower()).first()

        if user and user.check_password(form.password.data) and user.is_admin:
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
            flash('Invalid email or password, or you do not have admin privileges.', 'danger')
    return render_template('admin_login.html', form=form)

@admin_bp.route('/logout')
@login_required
def admin_logout():
    # Only log out if the current user is an admin
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
@login_required # This is now technically redundant due to before_request, but good for clarity
def dashboard():
    user_count = User.query.count()
    # Assuming 'pending', 'under_review', etc. are actual statuses in your Claim model
    claim_stats = {
        'total': Claim.query.count(),
        'pending': Claim.query.filter_by(status='pending').count(),
        'under_review': Claim.query.filter_by(status='under_review').count(),
        'approved': Claim.query.filter_by(status='approved').count(),
        'rejected': Claim.query.filter_by(status='rejected').count(),
        'resolved': Claim.query.filter_by(status='resolved').count()
    }
    recent_claims = Claim.query.order_by(Claim.reported_at.desc()).limit(5).all()
    recent_users = User.query.order_by(User.registered_at.desc()).limit(5).all()

    return render_template('admin_dashboard.html',
                           user_count=user_count,
                           claim_stats=claim_stats,
                           recent_claims=recent_claims,
                           recent_users=recent_users)

@admin_bp.route('/manage_users')
@login_required
def manage_users():
    users = User.query.all()
    roles = Role.query.all() # Fetch roles for display/selection
    return render_template('admin/manage_users.html', users=users, roles=roles)


@admin_bp.route('/user/<int:user_id>/assign_role', methods=['GET', 'POST'])
@login_required
def assign_role(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Assuming a form or direct request data to change role
        new_role_id = request.form.get('role_id', type=int)
        if new_role_id:
            new_role = Role.query.get(new_role_id)
            if new_role:
                user.role = new_role # Assign the role object directly
                user.is_admin = new_role.is_admin # Update is_admin based on the selected role
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

    # For GET request, render a form or provide data for a modal
    roles = Role.query.all()
    return render_template('admin/assign_role_modal.html', user=user, roles=roles) # You'd need this template


@admin_bp.route('/audit_logs')
@login_required
def audit_logs():
    logs = AdminAuditLog.query.order_by(AdminAuditLog.timestamp.desc()).all()
    return render_template('admin/audit_logs.html', logs=logs)

@admin_bp.route('/system_settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    # Example: A simple page for system settings
    # You would typically have a form here to update settings
    if request.method == 'POST':
        flash('System settings updated successfully!', 'success')
        # Implement actual setting update logic here
    return render_template('admin/system_settings.html') # Assuming you have this template


@admin_bp.route('/manage_claims')
@login_required
def manage_claims():
    claims = Claim.query.order_by(Claim.reported_at.desc()).all()
    return render_template('admin/manage_claims.html', claims=claims)

@admin_bp.route('/claim/<int:claim_id>/resolve', methods=['GET', 'POST'])
@login_required
def resolve_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    form = ResolveClaimForm()
    
    if form.validate_on_submit():
        claim.status = form.resolution_type.data # Using resolution_type as the new status
        claim.admin_notes = form.admin_notes.data # Assuming admin_notes is a field in the form
        claim.resolved_by_admin_id = current_user.user_id
        claim.resolved_at = func.now() # Use func.now() for database timestamp

        db.session.commit()

        log = AdminAuditLog(
            admin_id=current_user.user_id,
            action=f"Resolved claim {claim.claim_id}",
            details=f"Claim ID: {claim_id}, New Status: {claim.status}"
        )
        db.session.add(log)
        db.session.commit()
        flash(f'Claim {claim_id} resolved successfully!', 'success')
        return redirect(url_for('admin.manage_claims'))
    
    return render_template('admin/resolve_claim.html', form=form, claim=claim)

@admin_bp.route('/user/<int:user_id>/claims')
@login_required
def user_claims(user_id):
    user = User.query.get_or_404(user_id)
    claims = Claim.query.filter_by(user_id=user_id).order_by(Claim.reported_at.desc()).all()
    return render_template('admin/user_claims.html', user=user, claims=claims)

@admin_bp.route('/system_status')
@login_required
def system_status():
    # This route would display system health, database status, etc.
    # You'd add logic here to gather relevant system information.
    return render_template('admin/system_status.html')

# Add a route for deleting users
@admin_bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    # Prevent admin from deleting themselves or the last admin
    if user.user_id == current_user.user_id:
        flash("You cannot delete your own admin account!", "danger")
        return redirect(url_for('admin.manage_users'))
    
    # Optional: Prevent deleting the last admin account
    # if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
    #     flash("Cannot delete the last admin account!", "danger")
    #     return redirect(url_for('admin.manage_users'))

    log = AdminAuditLog(
        admin_id=current_user.user_id,
        action=f"Deleted user {user.email}",
        details=f"User ID: {user.user_id}"
    )
    db.session.add(log)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.email} deleted successfully!', 'success')
    return redirect(url_for('admin.manage_users'))