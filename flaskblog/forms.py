from ast import Pass, Sub
from wsgiref.validate import validator
from click import password_option
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    BooleanField,
    FileField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User

from flask_wtf.file import FileAllowed
from flask_login import current_user, AnonymousUserMixin


class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.username = "Guest"
        self.email = "guest@gmail.com"

def validate_field(reset=False):
    def _validate_field(form, field):
        user = None
        if field.label.text == "email" and field.data != current_user.email:
            user = User.query.filter_by(email=field.data).first()
        elif field.label.text == "Username" and field.data != current_user.username:
            user = User.query.filter_by(username=field.data).first()
        if not reset:
            if user:
                raise ValidationError(
                    f"That {field.label.text} is taken. Please choose a different one"
                )
        else:
            if user is None:
                raise ValidationError(
                    f"There is no account with that email. You must register first."
                )
    return _validate_field


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20), validate_field()]
    )

    email = StringField("email", validators=[DataRequired(), Email(), validate_field()])

    # Put the regexp validator
    password = PasswordField("Password", validators=[DataRequired()])

    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])

    password = PasswordField("Password", validators=[DataRequired()])

    remember = BooleanField("Remember Me")

    submit = SubmitField("Login")


class UpdateAccountForm(FlaskForm):

    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20), validate_field()]
    )

    email = StringField("email", validators=[DataRequired(), Email(), validate_field()])

    picture = FileField(
        "Update Profile Picture", validators=[FileAllowed(["jpg", "png"])]
    )

    submit = SubmitField("Update")


class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    submit = SubmitField("Post Me")

class RequestResetForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(), Email(),validate_field(reset=True)])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Reset Password')