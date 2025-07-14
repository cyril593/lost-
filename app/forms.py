from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, FileField, SubmitField, DateField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp, Optional
from flask_wtf.file import FileAllowed
import os
from PIL import Image
from flask import current_app


STRONG_PASSWORD_REGEX = r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+])'
STRONG_PASSWORD_MESSAGE = 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(STRONG_PASSWORD_REGEX, message=STRONG_PASSWORD_MESSAGE)
    ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    student_id = StringField('Student ID (Optional)', validators=[Length(max=20), Optional()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(STRONG_PASSWORD_REGEX, message=STRONG_PASSWORD_MESSAGE)
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class ItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10, max=500)])
    
    item_type = SelectField('Item Type', choices=[
        ('found', 'Found Item'),
        ('lost', 'Lost Item')
    ], validators=[DataRequired()])

    category = SelectField('Category', choices=[
        ('electronics', 'Electronics'),
        ('documents', 'Documents'),
        ('clothing', 'Clothing'),
        ('accessories', 'Accessories'),
        ('keys', 'Keys'),
        ('wallets', 'Wallets/Purses'),
        ('bags', 'Bags/Backpacks'),
        ('jewelry', 'Jewelry'),
        ('books', 'Books/Stationery'),
        ('sporting_goods', 'Sporting Goods'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    location_found = StringField('Location (Where Item Was Found/Lost)', validators=[DataRequired(), Length(min=2, max=100)])
    date_found = DateField('Date Found/Lost (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired()])
    image = FileField('Upload Image (Optional)', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'jfif'], 'Images only!')])
    submit = SubmitField('Report Item')

class ClaimForm(FlaskForm):
    claim_details = TextAreaField('Claim Details (Describe the item and provide proof of ownership)', validators=[DataRequired(), Length(min=20, max=1000)])
    submit = SubmitField('Submit Claim')

class MessageForm(FlaskForm):
    message_text = TextAreaField('Message', validators=[DataRequired(), Length(min=5, max=500)])
    submit = SubmitField('Send Message')

class ReviewForm(FlaskForm):
    rating = SelectField('Rating', choices=[(1, '1 Star'), (2, '2 Stars'), (3, '3 Stars'), (4, '4 Stars'), (5, '5 Stars')], coerce=int, validators=[DataRequired()])
    review_text = TextAreaField('Review (Optional)', validators=[Length(max=500)])
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
        Regexp(STRONG_PASSWORD_REGEX, message=STRONG_PASSWORD_MESSAGE)
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')
