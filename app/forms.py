# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp, Optional
from flask_wtf.file import FileAllowed
import os
from PIL import Image
from flask import current_app
from app.__init__ import get_item_classifier


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    student_id = StringField('Student ID (Optional)', validators=[Length(max=20), Optional()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])',
               message='Password must contain at least one uppercase letter, one lowercase letter, and one number.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data.strip().lower()).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one or login.')

    def validate_student_id(self, student_id):
        if student_id.data:
            from app.models import User
            user = User.query.filter_by(student_id=student_id.data).first()
            if user:
                raise ValidationError('This Student ID is already registered. Please check your input.')


class ItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])
    
    category = SelectField('Category', choices=[
        ('electronics', 'Electronics'),
        ('documents', 'Documents'),
        ('clothing', 'Clothing'),
        ('accessories', 'Accessories'),
        ('personal_belongings', 'Personal Belongings'),
        ('stationery', 'Stationery'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    item_type = SelectField('Type', choices=[('found', 'Found Item'), ('lost', 'Lost Item')], validators=[DataRequired()])
    
    location_found = StringField('Location (Where it was found/lost)', validators=[DataRequired(), Length(max=100)])
    date_found = StringField('Date (When it was found/lost - YYYY-MM-DD)', validators=[DataRequired(), Regexp(r'^\d{4}-\d{2}-\d{2}$', message='Date must be in YYYY-MM-DD format')])
    
    image = FileField('Upload Image (Optional)', validators=[
        FileAllowed(['jpg', 'png', 'jpeg','jfif'], 'Images only!')
    ])
    auto_categorize_image = BooleanField('Auto-Categorize from Image (Uses AI)')
    
    submit = SubmitField('Report Item')

    def validate_image(self, field):
        if field.data:
            max_upload_size = current_app.config.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024)
            if field.data.content_length > max_upload_size:
                raise ValidationError(f'File size exceeds the limit of {max_upload_size / (1024 * 1024):.0f}MB.')

            try:
                Image.open(field.data)
            except Exception:
                raise ValidationError('Invalid image file.')
            field.data.seek(0)

    def auto_categorize(self, image_file): 
       
        try: #
            classifier = get_item_classifier() 
            if classifier is None:
                return self.category.data 
            
            image = Image.open(image_file) 
            predicted_category = classifier.predict_category(image) 
            return predicted_category 
        except Exception as e: #
            current_app.logger.error(f"Auto-categorization failed: {e}") 
            return self.category.data 
class ClaimForm(FlaskForm):
    reason = TextAreaField('Reason for Claiming', validators=[DataRequired(), Length(max=500)],
                             render_kw={"placeholder": "Provide detailed reasons why this item is yours..."})
    contact_info = StringField('Contact Information (e.g., Phone, Email)', validators=[DataRequired(), Length(max=200)],
                               render_kw={"placeholder": "How can we contact you?"})
    submit = SubmitField('Submit Claim')

class MessageForm(FlaskForm):
    message = TextAreaField('Your Message', validators=[DataRequired(), Length(min=1, max=500)],
                            render_kw={"placeholder": "Type your message here..."})
    submit = SubmitField('Send Message')

class ReviewForm(FlaskForm):
    rating = SelectField('Rating', choices=[
        (5, '5 - Excellent'),
        (4, '4 - Good'),
        (3, '3 - Fair'),
        (2, '2 - Poor'),
        (1, '1 - Very Poor')
    ], coerce=int, validators=[DataRequired()])
    comments = TextAreaField('Comments (Optional)', validators=[Length(max=500)])
    submit = SubmitField('Submit Review')

class ResolveClaimForm(FlaskForm):
    resolution_type = SelectField('Resolution Type', choices=[
        ('returned_to_owner', 'Returned to owner'),
        ('kept', 'Item kept by finder'),
        ('donated', 'Item donated'),
        ('other', 'Other resolution')
    ], validators=[DataRequired()])
    admin_notes = TextAreaField('Admin Notes (Optional)', validators=[Length(max=500)],
                                render_kw={"placeholder": "Add any notes regarding the resolution..."})
    
    submit = SubmitField('Resolve Claim')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        from app.models import User
        user = User.query.filter_by(email=email.data.strip().lower()).first()
        if user is None:
            pass

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])',
               message='Password must contain at least one uppercase letter, one lowercase letter, and one number.')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')