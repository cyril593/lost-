from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user
from app.models import AdminAuditLog

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/audit-logs')
@login_required
def audit_logs():
    
    if not current_user.role or not current_user.role.is_admin:
        abort(403)
    
    logs = AdminAuditLog.query.order_by(AdminAuditLog.created_at.desc()).all()
    return render_template('admin/audit_logs.html', logs=logs)
