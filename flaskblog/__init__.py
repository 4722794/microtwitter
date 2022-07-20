from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
app.config["SECRET_KEY"] = "5791628bb0b13ce0c676dfde280ba245"
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "sqlite:///site.db"  # Story continues during deployment
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USER'] = 'slippingene@gmail.com'
app.config['MAIL_PASSWORD'] = ''
mail = Mail(app)

from flaskblog import routes
from flaskblog.forms import Anonymous

login_manager.anonymous_user = Anonymous
