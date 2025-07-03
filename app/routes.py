from flask import Blueprint, render_template, redirect, url_for, flash, current_app, request, send_from_directory
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from app import db
from app.forms import ItemForm
from app.models import Item
import os
import qrcode
from io import BytesIO
import base64

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/dashboard')
@login_required
def dashboard():
    items = Item.query.filter_by(user_id=current_user.user_id).all()
    return render_template('dashboard.html', items=items)

@main.route('/add-item', methods=['GET', 'POST'])
@login_required
def add_item():
    form = ItemForm()
    if form.validate_on_submit():
        # Ensure upload folder exists
        upload_folder = current_app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Create new item with qr_code set to None initially
        new_item = Item(
            user_id=current_user.user_id,
            item_type=form.item_type.data,
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            location=form.location.data,
            status=form.status.data,
            qr_code=None
        )

        # Save uploaded image with unique name
        if form.image.data:
            filename = secure_filename(form.image.data.filename)
            unique_name = f"{current_user.user_id}_{datetime.now().timestamp()}_{filename}"
            filepath = os.path.join(upload_folder, unique_name)
            form.image.data.save(filepath)
            new_item.image_path = unique_name

        db.session.add(new_item)
        db.session.flush()  # Get new_item.item_id before commit

        # Generate QR Code using item_id
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(f"item:{new_item.item_id}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = BytesIO()
        img.save(buffered)
        new_item.qr_code = base64.b64encode(buffered.getvalue()).decode()

        db.session.commit()

        flash('Item added successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('add_item.html', form=form)


@main.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
