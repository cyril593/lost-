from flask import (
    Blueprint, render_template, redirect, url_for, flash, current_app,
    request, send_from_directory, jsonify, abort
)
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from app.extensions import db, mail
from app.forms import (
    ItemForm, ClaimForm, MessageForm, ReviewForm, ResolveClaimForm
)
from app.models import Item, User, Claim, ClaimMessage, ClaimReview, AdminAuditLog, Notification, Role
import os
import qrcode
from io import BytesIO
import base64
from PIL import Image
import json
from threading import Thread
import uuid


from app.image_matcher import extract_features, find_matches

main = Blueprint('main', __name__)


def process_image_for_matching_background(app, item_id, image_filename, item_type):
    """
    Background task to extract image features and find potential matches.
    """
    with app.app_context():
        item = Item.query.get(item_id)
        if not item:
            app.logger.error(f"Background task: Item {item_id} not found.")
            return

        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)

        try:
            img = Image.open(image_path)
            features = extract_features(img)
            if features is not None:
                item.image_features = json.dumps(features)
                db.session.add(item)
                db.session.commit()
                app.logger.info(f"Image features extracted and saved for item {item_id}")

                if item_type == 'lost':
                    found_items = Item.query.filter_by(item_type='found').all()
                    matches = find_matches(features, found_items)

                    for found_item, score in matches:
                        message = f"Potential match found for your lost item '{item.item_name}' with found item '{found_item.item_name}' (Similarity: {score:.2f})."
                        notification = Notification(user_id=item.user_id, item_id=found_item.item_id, message=message)
                        db.session.add(notification)
                        app.logger.info(f"Notification created for user {item.user_id} regarding potential match.")
                    db.session.commit()
            else:
                app.logger.warning(f"Could not extract features for image: {image_filename}")
        except Exception as e:
            app.logger.error(f"Error in background image processing for item {item_id}: {e}")
            db.session.rollback()

@main.route('/')
@main.route('/home')
def home():
    """Displays the home page with recently added items."""
    recently_added_items = Item.query.order_by(Item.posted_at.desc()).limit(6).all()
    # CORRECTED: Changed 'home.html' to 'home.html' (already correct)
    return render_template('home.html', recently_added_items=recently_added_items)


@main.route('/register', methods=['GET', 'POST'])
def register():
    # CORRECTED: This redirect is fine, as it points to the blueprint route
    return redirect(url_for('auth.register'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    # CORRECTED: This redirect is fine, as it points to the blueprint route
    return redirect(url_for('auth.login'))

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    """Displays the user's personal dashboard."""
    total_lost = Item.query.filter_by(item_type='lost').count()
    total_found = Item.query.filter_by(item_type='found').count()

    my_reported_items = Item.query.filter_by(user_id=current_user.user_id).order_by(Item.posted_at.desc()).all()

    my_claims = Claim.query.filter_by(user_id=current_user.user_id).order_by(Claim.reported_at.desc()).all()

    claims_on_my_found_items = Claim.query.filter_by(finder_id=current_user.user_id).order_by(Claim.reported_at.desc()).all()

    pending_claims_count_for_user = Claim.query.filter(
        (Claim.user_id == current_user.user_id) | (Claim.finder_id == current_user.user_id),
        Claim.status == 'pending'
    ).count()

    summary = {
        'total_lost': total_lost,
        'total_found': total_found,
        'pending_claims_for_you': pending_claims_count_for_user,
        'your_lost': len([item for item in my_reported_items if item.item_type == 'lost']),
        'your_found': len([item for item in my_reported_items if item.item_type == 'found']),
        'your_claims_made': len(my_claims),
        'claims_on_your_found_items': len(claims_on_my_found_items)
    }
    # CORRECTED: Changed 'dashboard.html' to 'dashboard.html' (already correct)
    return render_template('dashboard.html', summary=summary,
                           my_reported_items=my_reported_items,
                           my_claims=my_claims,
                           claims_on_my_found_items=claims_on_my_found_items)


@main.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    """Allows users to report a lost or found item."""
    form = ItemForm()
    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            image_file = form.image.data
            filename = secure_filename(image_file.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            image_file.save(image_path)
            image_filename = unique_filename

        new_item = Item(
            item_name=form.item_name.data,
            description=form.description.data,
            item_type=form.item_type.data,
            category=form.category.data,
            location_found=form.location_found.data,
            date_found=form.date_found.data,
            user_id=current_user.user_id,
            image_filename=image_filename,
            posted_at=datetime.utcnow()
        )
        db.session.add(new_item)
        db.session.commit()

        qr_data = url_for('main.item_detail', item_id=new_item.item_id, _external=True)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        new_item.qr_code = base64.b64encode(buffered.getvalue()).decode('utf-8')
        db.session.commit()

        flash('Item reported successfully!', 'success')

        if new_item.image_filename:
            app_instance = current_app._get_current_object()
            Thread(target=process_image_for_matching_background, args=(app_instance, new_item.item_id, new_item.image_filename, new_item.item_type)).start()

        return redirect(url_for('main.dashboard'))
    # CORRECTED: Changed 'add_item.html' to 'add_item.html' (already correct)
    return render_template('add_item.html', form=form)

@main.route('/items', methods=['GET'])
def all_items():
    """Displays a paginated list of all lost and found items."""
    page = request.args.get('page', 1, type=int)
    per_page = 9
    items_pagination = Item.query.order_by(Item.posted_at.desc())\
                                   .paginate(page=page, per_page=per_page, error_out=False)
    # CORRECTED: Changed 'items_list.html' to 'items_list.html' (already correct)
    return render_template('items_list.html',
                           items=items_pagination.items,
                           pagination=items_pagination)

@main.route('/item/<int:item_id>')
def item_detail(item_id):
    """Displays details of a specific item."""
    item = Item.query.get_or_404(item_id)
    claim = None
    if current_user.is_authenticated:
        claim = current_user.get_claim_for_item(item_id)
    # CORRECTED: Changed 'item_details.html' to 'item_details.html' (already correct)
    return render_template('item_details.html', item=item, claim=claim)

@main.route('/claim_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def claim_item(item_id):
    """Allows a user to submit a claim for an item."""
    item = Item.query.get_or_404(item_id)
    form = ClaimForm()

    if item.user_id == current_user.user_id:
        flash('You cannot claim an item you reported.', 'warning')
        return redirect(url_for('main.item_detail', item_id=item_id))

    existing_claim = Claim.query.filter_by(user_id=current_user.user_id, item_id=item_id).first()
    if existing_claim:
        flash('You have already submitted a claim for this item. You can view its status on your dashboard.', 'info')
        return redirect(url_for('main.item_detail', item_id=item_id))

    if form.validate_on_submit():
        proof_filename = None
        # Assuming a FileField named 'proof_file' in ClaimForm, but it's not defined in forms.py
        # If you intend to have a proof file upload, you need to add it to ClaimForm in forms.py
        # For now, I'm commenting out the proof file handling to avoid errors.
        # if 'proof_file' in request.files and request.files['proof_file']:
        #     proof_file = request.files['proof_file']
        #     filename = secure_filename(proof_file.filename)
        #     unique_filename = str(uuid.uuid4()) + '_' + filename
        #     proof_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'proofs', unique_filename)
        #     os.makedirs(os.path.dirname(proof_path), exist_ok=True)
        #     proof_file.save(proof_path)
        #     proof_filename = unique_filename

        new_claim = Claim(
            item_id=item.item_id,
            user_id=current_user.user_id,
            claim_details=form.claim_details.data,
            status='pending',
            reported_at=datetime.utcnow(),
            finder_id=item.user_id,
            proof_filename=proof_filename
        )
        db.session.add(new_claim)
        db.session.commit()

        flash('Your claim has been submitted and is awaiting review.', 'success')

        if item.reporter:
            notification_message = f"A new claim has been submitted for your item: '{item.item_name}' by {current_user.name}."
            notification = Notification(user_id=item.reporter.user_id, item_id=item.item_id, message=notification_message)
            db.session.add(notification)
            db.session.commit()

        return redirect(url_for('main.dashboard'))
    # CORRECTED: Changed 'claim_form.html' to 'claim_form.html' (assuming this template exists)
    return render_template('claim_form.html', form=form, item=item)


@main.route('/claim_messages/<int:claim_id>', methods=['GET', 'POST'])
@login_required
def claim_messages(claim_id):
    """Displays messages for a claim and allows sending new messages."""
    claim = Claim.query.get_or_404(claim_id)

    if not (current_user.user_id == claim.user_id or
            current_user.user_id == claim.finder_id or
            current_user.is_admin):
        flash('You are not authorized to view messages for this claim.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = MessageForm()
    if form.validate_on_submit():
        new_message = ClaimMessage(
            claim_id=claim.claim_id,
            sender_id=current_user.user_id,
            message_text=form.message_text.data,
            timestamp=datetime.utcnow()
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')

        recipient = None
        if current_user.user_id == claim.user_id:
            recipient = claim.finder
        elif current_user.user_id == claim.finder_id:
            recipient = claim.claimant
        elif current_user.is_admin:
            notification_to_claimer = Notification(user_id=claim.user_id, item_id=claim.item.item_id, message=f"Admin sent a message regarding your claim for '{claim.item.item_name}'.")
            db.session.add(notification_to_claimer)
            if claim.finder_id != claim.user_id:
                notification_to_finder = Notification(user_id=claim.finder_id, item_id=claim.item.item_id, message=f"Admin sent a message regarding a claim on your item '{claim.item.item_name}'.")
                db.session.add(notification_to_finder)
            db.session.commit()
            recipient = None

        if recipient:
            notification_message = f"New message regarding claim #{claim.claim_id} for item '{claim.item.item_name}'."
            notification = Notification(user_id=recipient.user_id, item_id=claim.item.item_id, message=notification_message)
            db.session.add(notification)
            db.session.commit()

        return redirect(url_for('main.claim_messages', claim_id=claim.claim_id))

    messages = ClaimMessage.query.filter_by(claim_id=claim_id).order_by(ClaimMessage.timestamp.asc()).all()
    # CORRECTED: Changed 'claim_messages.html' to 'claim_messages.html' (already correct)
    return render_template('claim_messages.html', claim=claim, messages=messages, form=form)


@main.route('/review_claim/<int:claim_id>', methods=['GET', 'POST'])
@login_required
def review_claim(claim_id):
    """Allows a user to review a resolved claim."""
    claim = Claim.query.get_or_404(claim_id)

    if not (current_user.user_id == claim.user_id and claim.status == 'resolved'):
        flash('You are not authorized to review this claim, or it is not yet resolved.', 'danger')
        return redirect(url_for('main.dashboard'))

    if claim.reviews:
        flash('You have already submitted a review for this claim.', 'info')
        return redirect(url_for('main.item_detail', item_id=claim.item_id))

    form = ReviewForm()
    if form.validate_on_submit():
        new_review = ClaimReview(
            claim_id=claim.claim_id,
            reviewer_id=current_user.user_id,
            rating=form.rating.data,
            review_text=form.review_text.data,
            reviewed_at=datetime.utcnow()
        )
        db.session.add(new_review)
        db.session.commit()
        flash('Thank you for your feedback! Your review has been submitted.', 'success')
        return redirect(url_for('main.dashboard'))

    # CORRECTED: Changed 'review_claim.html' to 'review_claim.html' (already correct)
    return render_template('review_claim.html', form=form, claim=claim)


@main.route('/resolve_claim/<int:claim_id>', methods=['GET', 'POST'])
@login_required
def resolve_claim(claim_id):
    """Allows the item owner or admin to resolve a claim."""
    claim = Claim.query.get_or_404(claim_id)

    if claim.finder_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to resolve this claim.', 'danger')
        return redirect(url_for('main.item_detail', item_id=claim.item_id))

    if claim.status == 'resolved':
        flash('This claim has already been resolved.', 'info')
        return redirect(url_for('main.item_detail', item_id=claim.item_id))

    form = ResolveClaimForm()
    if form.validate_on_submit():
        claim.resolution_type = form.resolution_type.data
        claim.admin_notes = form.admin_notes.data
        claim.resolved_by_admin_id = current_user.user_id
        claim.resolved_at = datetime.utcnow()
        claim.status = 'resolved'

        db.session.commit()
        flash('Claim resolved successfully!', 'success')

        if claim.claimant:
            notification_message = f"Your claim for '{claim.item.item_name}' has been resolved with type: {claim.resolution_type.replace('_', ' ').title()}."
            notification = Notification(user_id=claim.claimant.user_id, item_id=claim.item.item_id, message=notification_message)
            db.session.add(notification)
            db.session.commit()

        return redirect(url_for('main.item_detail', item_id=claim.item.item_id))

    if claim.resolution_type:
        form.resolution_type.data = claim.resolution_type
    if claim.admin_notes:
        form.admin_notes.data = claim.admin_notes

    # CORRECTED: Changed 'resolve_claim.html' to 'resolve_claim.html' (already correct)
    return render_template('resolve_claim.html', form=form, claim=claim)


@main.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    """Allows the item's reporter or an admin to edit item details."""
    item = Item.query.get_or_404(item_id)

    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to edit this item.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = ItemForm(obj=item)
    if request.method == 'GET':
        form.item_type.data = item.item_type
        form.category.data = item.category
        form.date_found.data = item.date_found

    if form.validate_on_submit():
        item.item_name = form.item_name.data
        item.description = form.description.data
        item.item_type = form.item_type.data
        item.location_found = form.location_found.data
        item.date_found = form.date_found.data

        if form.image.data:
            if item.image_filename:
                old_image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], item.image_filename)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
                    current_app.logger.info(f"Deleted old image file: {old_image_path}")

            image_file = form.image.data
            filename = secure_filename(image_file.filename)
            unique_filename = str(uuid.uuid4()) + '_' + filename
            image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            image_file.save(image_path)
            item.image_filename = unique_filename

            app_instance = current_app._get_current_object()
            Thread(target=process_image_for_matching_background, args=(app_instance, item.item_id, item.image_filename, item.item_type)).start()

        item.category = form.category.data

        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    # CORRECTED: Changed 'edit_item.html' to 'edit_item.html' (already correct)
    return render_template('edit_item.html', form=form, item=item)


@main.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    """Allows the item's reporter or an admin to delete an item."""
    item = Item.query.get_or_404(item_id)

    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to delete this item.', 'danger')
        return redirect(url_for('main.dashboard'))

    if item.image_filename:
        image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], item.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
            current_app.logger.info(f"Deleted image file: {image_path}")

    if current_user.is_admin:
        admin_log = AdminAuditLog(
            admin_id=current_user.user_id,
            action=f"Deleted Item {item.item_id}",
            details=f"Item '{item.item_name}' (Type: {item.item_type}) deleted by admin."
        )
        db.session.add(admin_log)

    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    """Serves uploaded files from the UPLOAD_FOLDER."""
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@main.route('/uploaded_proof/<filename>')
def uploaded_proof(filename):
    """Serves uploaded proof files from the UPLOAD_FOLDER/proofs subfolder."""
    # CORRECTED: Assuming 'proofs' subdirectory exists within UPLOAD_FOLDER
    return send_from_directory(os.path.join(current_app.config['UPLOAD_FOLDER'], 'proofs'), filename)

@main.route('/view_qr_code/<int:item_id>')
@login_required
def view_qr_code(item_id):
    """Displays the QR code for a specific item."""
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to view the QR code for this item.', 'danger')
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    if item.qr_code:
        qr_code_base64 = item.qr_code
        item_detail_url = url_for('main.item_detail', item_id=item.item_id, _external=True)
        # CORRECTED: Changed 'view_qrcode.html' to 'view_qrcode.html' (already correct)
        return render_template('view_qrcode.html', qr_code=qr_code_base64, item=item, item_detail_url=item_detail_url)
    flash('QR Code not found for this item.', 'warning')
    return redirect(url_for('main.item_detail', item_id=item.item_id))


@main.route('/notifications')
@login_required
def notifications():
    """Displays user notifications."""
    user_notifications = Notification.query.filter_by(
        user_id=current_user.user_id
    ).order_by(Notification.timestamp.desc()).all()
    # CORRECTED: Changed 'notifications.html' to 'notifications.html' (already correct)
    return render_template('notifications.html', notifications=user_notifications)


@main.route('/notification/<int:notification_id>/mark_read')
@login_required
def mark_notification_read(notification_id):
    """Marks a specific notification as read."""
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.user_id:
        abort(403)

    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('main.notifications'))


@main.route('/api/predict_category', methods=['POST'])
def predict_category_api():
    """API endpoint for image category prediction."""
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    file = request.files['image']
    if not file:
        return jsonify({'error': 'No selected file'}), 400

    try:
        classifier = current_app.extensions.get('classifier')
        if classifier and classifier._model: # Access the internal _model to check if loaded
            # Read image data as bytes for the predict method
            img_data = file.read()
            prediction_result = classifier.predict(img_data)
            if prediction_result:
                # The predict method in cnn.py returns a dictionary with 'matches'
                # You might want to adjust this based on what 'predict_category' was supposed to do.
                # For now, returning the full prediction result.
                return jsonify(prediction_result), 200
            else:
                return jsonify({'error': 'Prediction failed or returned no results.'}), 500
        else:
            current_app.logger.error("CNN classifier model not loaded or available for prediction.")
            return jsonify({'error': 'Classifier not loaded or available.'}), 500
    except Exception as e:
        current_app.logger.error(f"Error during category prediction: {e}")
        return jsonify({'error': f'Failed to process image for prediction: {str(e)}'}), 500

@main.route('/schedule_pickup/<int:item_id>', methods=['GET', 'POST'])
@login_required
def schedule_pickup(item_id):
    """Placeholder for scheduling item pickup."""
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.user_id and not current_user.is_admin:
        flash('You are not authorized to schedule pickup for this item.', 'danger')
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    if request.method == 'POST':
        pickup_date = request.form.get('pickup_date')
        claimant_name = request.form.get('claimant_name')
        generate_qr = request.form.get('generate_qr') == 'yes'

        flash(f"Pickup scheduled for {pickup_date} with {claimant_name}. QR generation: {generate_qr}", "success")
        return redirect(url_for('main.item_detail', item_id=item.item_id))

    # CORRECTED: Changed 'schedule_pickup.html' to 'schedule_pickup.html' (already correct)
    return render_template('schedule_pickup.html', item=item)
