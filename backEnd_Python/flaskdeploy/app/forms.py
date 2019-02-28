from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app import User, Conta

class LoginForm(FlaskForm):
    username = StringField('Username (email)', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('A como devemos nos referir:', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    password2 = PasswordField(
        'Repita a Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')

    def validate_username(self, username):
        #existing_user = User.objects(username=username.data).first()
        existing_user = Conta.objects(userSetting__username = username.data)
        print(existing_user)
        print(username.data)
        #user = UserDB.getUserByParameter({"name":username.data})
#        //user = User.query.filter_by(username=username.data).first()
        #if existing_user not None:
        if existing_user: # is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        #existing_user = User.objects(email=email.data).first()
        existing_user = Conta.objects(userSetting__email = email.data)
        print(email.data)
        print (existing_user)
        #user = UserDB.getUserByParameter({"email":email.data})
        #user = User.query.filter_by(email=email.data).first()
        #if user is not None:
        if existing_user: #is not None:
            raise ValidationError('Please use a different email address.')
