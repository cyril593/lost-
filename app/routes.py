# app/routes.py
from flask import (
    Blueprint, render_template, redirect, url_for, flash, current_app,
    request, send_from_directory, jsonify, abort, send_file
)
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from app.extensions import db, mail
from app.forms import (
    ItemForm, ClaimForm, MessageForm, ReviewForm, ResolveClaimForm, AdminLoginForm, LoginForm # Ensure LoginForm is imported
)
from app.models import Item, User, Claim, ClaimMessage, ClaimReview, Role, AdminAuditLog
import os
import qrcode
from io import BytesIO
import base64
from PIL import Image

from app.__init__ import get_item_classifier
from flask_mail import Message
from threading import Thread 
import uuid 
from functools import wraps  

# Define a simple decorator for admin access if not using blueprint.before_request (though admin.py has it)
# def admin_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if not current_user.is_authenticated or not current_user.is_admin:
#             flash('You do not have administrative access to view this page.', 'danger')
#             return redirect(url_for('main.home')) # Redirect to home or login
#         return f(*args, **kwargs)
#     return decorated_function


main = Blueprint('main', __name__)

# The 'admin' blueprint is defined in admin.py and imported in __init__.py


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, recipients, text_body, html_body):
    msg = Message(subject, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(current_app._get_current_object(), msg)).start()

@main.route('/')
@main.route('/home')
def home():
    if current_user.is_authenticated:
        # Fetch items for logged-in users
        items = Item.query.order_by(Item.reported_at.desc()).all()
    else:
        # Fetch items for guests (maybe only public ones)
        items = Item.query.order_by(Item.reported_at.desc()).all() # Or a subset for public

    # This passes all items, consider pagination for large datasets
    return render_template('home.html', items=items)

# Renamed add_item to report_item to match the original provided code's route name
@main.route('/report_item', methods=['GET', 'POST'])
@login_required
def report_item():
    form = ItemForm()
    if form.validate_on_submit():
        image_filename = None
        item_category = form.category.data

        if form.image.data:
            # Save the image and get its filename
            # This part needs to be robust, using secure_filename and proper path
            filename = secure_filename(form.image.data.filename)
            # Define upload folder relative to app instance
            upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
            os.makedirs(upload_folder, exist_ok=True)
            image_path = os.path.join(upload_folder, filename)
            form.image.data.save(image_path)
            image_filename = filename

            if form.auto_categorize_image.data:
                # Pass the actual file stream to auto_categorize
                # Need to reopen the stream or pass the path
                # For simplicity here, we'll load from path, but direct stream is better
                try:
                    with open(image_path, 'rb') as f:
                        item_category = form.auto_categorize(f)
                except Exception as e:
                    current_app.logger.error(f"Error during post-upload auto-categorization: {e}")
                    item_category = form.category.data # Fallback to manual selection


        new_item = Item(
            item_name=form.item_name.data,
            # Assuming item_name can also be the title for simplicity, or add a dedicated title field to form
            title=form.item_name.data, # Added for consistency with new Item model field
            description=form.description.data,
            category=item_category, # Use auto-categorized or manual
            image_filename=image_filename,
            location_found=form.location_found.data,
            date_found=datetime.strptime(form.date_found.data, '%Y-%m-%d').date(),
            user_id=current_user.user_id,
            status='found', # Default status for a newly reported item
            item_type='found' # Assuming reported items are 'found' by default
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Item reported successfully!', 'success')
        return redirect(url_for('main.home'))
    # FIX: Ensure this renders 'add_item.html' as per the prompt's request for template filename matching
    return render_template('add_item.html', form=form) 

@main.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    # Fetch related claims, messages, etc.
    claims = Claim.query.filter_by(item_id=item_id).all()
    # You might want to filter claims based on status or user permissions
    return render_template('item_details.html', item=item, claims=claims) # Assuming template is item_details.html

# New route for all items
@main.route('/all_items')
def all_items():
    items = Item.query.order_by(Item.reported_at.desc()).all()
    # You would typically add pagination here for a real application
    return render_template('items_list.html', items=items) # Assuming an items_list.html template exists

# New route for QR code generation
@main.route('/item/<int:item_id>/qr_code')
def view_qr_code(item_id):
    item = Item.query.get_or_404(item_id)
    # Generate QR code for the item's detail page URL
    qr_data = url_for('main.item_detail', item_id=item.item_id, _external=True)
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    # Encode for embedding in HTML or send as file
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('qr_code.html', item=item, qr_code_base64=qr_code_base64) # Assuming qr_code.html template exists


# New route for image category prediction (if using AJAX)
@main.route('/predict_category', methods=['POST'])
def predict_category():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400
    
    image_file = request.files['image']
    if image_file.filename == '':
        return jsonify({'error': 'No selected image file'}), 400
    
    if image_file:
        try:
            # Use the auto_categorize logic from ItemForm
            # Create a dummy form object to use its method
            form = ItemForm()
            predicted_category = form.auto_categorize(image_file)
            return jsonify({'category': predicted_category})
        except Exception as e:
            current_app.logger.error(f"Error during category prediction: {e}")
            return jsonify({'error': 'Prediction failed', 'details': str(e)}), 500
    return jsonify({'error': 'Invalid image file'}), 400


@main.route('/item/<int:item_id>/claim', methods=['GET', 'POST'])
@login_required
def make_claim(item_id):
    item = Item.query.get_or_404(item_id)
    form = ClaimForm()
    
    if item.user_id == current_user.user_id:
        flash('You cannot claim an item you reported yourself.', 'warning')
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    # Check if user already has a pending claim for this item
    existing_claim = Claim.query.filter_by(
        item_id=item_id,
        user_id=current_user.user_id,
        status='pending'
    ).first()

    if existing_claim:
        flash('You already have a pending claim for this item.', 'info')
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    if form.validate_on_submit():
        claim_proof_filename = None
        if form.proof.data:
            filename = secure_filename(form.proof.data.filename)
            upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
            os.makedirs(upload_folder, exist_ok=True)
            proof_path = os.path.join(upload_folder, filename)
            form.proof.data.save(proof_path)
            claim_proof_filename = filename

        new_claim = Claim(
            item_id=item_id,
            user_id=current_user.user_id,
            reason=form.reason.data,
            proof_filename=claim_proof_filename,
            status='pending'
        )
        db.session.add(new_claim)
        db.session.commit()
        flash('Your claim has been submitted and is pending review.', 'success')

        # Notify the item reporter about the new claim
        reporter_email = item.user.email
        subject = f"New Claim Submitted for Your Item: {item.item_name}"
        text_body = render_template('email/new_claim_notification.txt', item=item, claim=new_claim, claimer=current_user)
        html_body = render_template('email/new_claim_notification.html', item=item, claim=new_claim, claimer=current_user)
        send_email(subject, [reporter_email], text_body, html_body)

        return redirect(url_for('main.item_detail', item_id=item.item_id))
    
    return render_template('make_claim.html', form=form, item=item)

@main.route('/uploads/<filename>')
def uploaded_file(filename):
    # Ensure this serves from a secure location
    return send_from_directory(os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER']), filename)

@main.route('/dashboard')
@login_required
def dashboard():
    # Items reported by the current user
    reported_items = Item.query.filter_by(user_id=current_user.user_id).order_by(Item.reported_at.desc()).all()
    # Claims made by the current user
    my_claims = Claim.query.filter_by(user_id=current_user.user_id).order_by(Claim.reported_at.desc()).all()
    # Claims on items reported by the current user (claims to review)
    claims_on_my_items = Claim.query.join(Item).filter(Item.user_id == current_user.user_id).order_by(Claim.reported_at.desc()).all()

    # Placeholder for summary data (replace with actual queries if needed)
    summary = {
        'total_lost': 0, # Example: Item.query.filter_by(item_type='lost', user_id=current_user.user_id).count()
        'total_found': len(reported_items),
        'pending_claims': Claim.query.filter(
            (Claim.item.has(user_id=current_user.user_id)) & (Claim.status == 'pending')
        ).count(),
        'items_to_pickup': 0 # Example: Claims with status 'approved' by current_user as claimant
    }

    return render_template('dashboard.html', 
                           reported_items=reported_items,
                           my_claims=my_claims,
                           claims_on_my_items=claims_on_my_items,
                           summary=summary)

@main.route('/claim/<int:claim_id>/messages', methods=['GET', 'POST'])
@login_required
def claim_messages(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    
    # Authorization check: only claimer, item reporter, or admin can see messages
    if not (claim.user_id == current_user.user_id or 
            claim.item.user_id == current_user.user_id or 
            current_user.is_admin):
        flash('You are not authorized to view messages for this claim.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = MessageForm()
    if form.validate_on_submit():
        new_message = ClaimMessage(
            claim_id=claim.claim_id,
            sender_id=current_user.user_id,
            content=form.message.data
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')

        # Notify the other party
        recipient = claim.user if claim.item.user_id == current_user.user_id else claim.item.user
        subject = f"New Message for Claim #{claim.claim_id} on item: {claim.item.item_name}"
        text_body = render_template('email/new_message_notification.txt', claim=claim, message=new_message)
        html_body = render_template('email/new_message_notification.html', claim=claim, message=new_message)
        send_email(subject, [recipient.email], text_body, html_body)

        return redirect(url_for('main.claim_messages', claim_id=claim.claim_id))
    
    messages = ClaimMessage.query.filter_by(claim_id=claim_id).order_by(ClaimMessage.timestamp.asc()).all()
    # FIX: Ensure the back button in claim_messages.html links to item_detail, not item_details
    return render_template('claim_messages.html', claim=claim, messages=messages, form=form)

@main.route('/claim/<int:claim_id>/review', methods=['GET', 'POST'])
@login_required
def review_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)

    # Authorization check: only the item reporter or the claimer can review a RESOLVED claim
    if not ((claim.item.user_id == current_user.user_id or claim.user_id == current_user.user_id) and claim.status == 'resolved'):
        flash('You can only review resolved claims related to your reported items or your claims.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Prevent multiple reviews from the same user for the same claim
    existing_review = ClaimReview.query.filter_by(claim_id=claim_id, reviewer_id=current_user.user_id).first()
    if existing_review:
        flash('You have already reviewed this claim.', 'info')
        return redirect(url_for('main.dashboard'))

    form = ReviewForm()
    if form.validate_on_submit():
        new_review = ClaimReview(
            claim_id=claim.claim_id,
            reviewer_id=current_user.user_id,
            rating=form.rating.data,
            comments=form.comments.data
        )
        db.session.add(new_review)
        db.session.commit()
        flash('Your review has been submitted!', 'success')
        return redirect(url_for('main.dashboard')) # Or redirect to claim detail
    
    return render_template('review_claim.html', form=form, claim=claim)


@main.route('/resolve-claim/<int:claim_id>', methods=['GET', 'POST'])
@login_required
def resolve_claim(claim_id):
    claim = Claim.query.get_or_404(claim_id)
    
    # Authorization check: only the item reporter or an admin can resolve this claim
    if claim.item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to resolve this claim.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Prevent resolving an already resolved or rejected claim
    if claim.status in ['resolved', 'rejected', 'approved']: # Assuming 'approved' also means no further action needed
        flash(f'This claim is already {claim.status}. No further action needed.', 'info')
        return redirect(url_for('main.item_detail', item_id=claim.item.item_id))

    form = ResolveClaimForm()
    if form.validate_on_submit():
        claim.status = form.resolution_type.data # Use the selected resolution_type as the new status
        claim.resolution_type = form.resolution_type.data # Store explicit resolution type
        claim.admin_notes = form.admin_notes.data # Store admin notes if provided
        claim.resolved_by_admin_id = current_user.user_id if current_user.is_admin else None # Log resolver if admin
        claim.resolved_at = datetime.utcnow() # Set resolution timestamp

        db.session.commit()

        # Log action for admin if it was an admin resolving
        if current_user.is_admin:
            log = AdminAuditLog(
                admin_id=current_user.user_id,
                action=f"Resolved claim {claim.claim_id}",
                details=f"Claim ID: {claim_id}, New Status: {claim.status}, Resolution Type: {claim.resolution_type}"
            )
            db.session.add(log)
            db.session.commit()
            
        flash(f'Claim {claim_id} resolved successfully!', 'success')
        return redirect(url_for('main.dashboard')) # Redirect to user's dashboard after resolution
    
    return render_template('resolve_claim.html', form=form, claim=claim)


@main.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Authorization check: Only the item's reporter or an admin can edit
    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to edit this item.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = ItemForm(obj=item) # Pre-populate form with existing item data
    if form.validate_on_submit():
        item.item_name = form.item_name.data
        item.description = form.description.data
        item.location_found = form.location_found.data
        item.date_found = datetime.strptime(form.date_found.data, '%Y-%m-%d').date()
        
        # Handle image update
        if form.image.data:
            # Delete old image if it exists
            if item.image_filename:
                old_image_path = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'], item.image_filename)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            filename = secure_filename(form.image.data.filename)
            upload_folder = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'])
            os.makedirs(upload_folder, exist_ok=True)
            image_path = os.path.join(upload_folder, filename)
            form.image.data.save(image_path)
            item.image_filename = filename

            if form.auto_categorize_image.data:
                try:
                    with open(image_path, 'rb') as f:
                        item.category = form.auto_categorize(f)
                except Exception as e:
                    current_app.logger.error(f"Error during post-upload auto-categorization for edit: {e}")
                    item.category = form.category.data # Fallback
            else:
                item.category = form.category.data # Use manual category if not auto-categorizing
        else:
            # If no new image, but auto_categorize_image was checked, it's a bit ambiguous
            # For now, if no new image, category remains as it was or is explicitly set by form.category.data
            item.category = form.category.data


        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('main.item_detail', item_id=item.item_id))
    
    # Format date for HTML form if editing
    if item.date_found:
        form.date_found.data = item.date_found.strftime('%Y-%m-%d')
    
    return render_template('edit_item.html', form=form, item=item)


@main.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Authorization check: Only the item's reporter or an admin can delete
    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to delete this item.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Delete associated claims first to avoid foreign key constraints
    Claim.query.filter_by(item_id=item.item_id).delete()
    
    # Delete image file if exists
    if item.image_filename:
        image_path = os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'], item.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(item)
    db.session.commit()
    flash('Item and associated claims deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))