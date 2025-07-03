from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password')])
    student_id = StringField('Student ID', validators=[Length(max=20)])  
    role = SelectField('Role', choices=[('user', 'Regular User'), ('admin', 'Administrator')])

class ItemForm(FlaskForm):
    item_type = SelectField('Type', choices=[
        ('lost', 'Lost Item'),
        ('found', 'Found Item')
    ], validators=[DataRequired()])
    
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    
    category = SelectField('Category', choices=[
        ('electronics', 'Electronics'),
        ('documents', 'Documents'),
        ('clothing', 'Clothing'),
        ('accessories', 'Accessories'),
        ('other', 'Other')
    ])
    
    location = StringField('Location', validators=[Length(max=100)])
    image = FileField('Item Image')
    

