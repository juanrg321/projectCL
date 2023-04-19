from flask import Flask, render_template, flash , request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
app = Flask(__name__)
app.config['SECRET_KEY'] = "key"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField("Username", validators = [DataRequired()])
    password = PasswordField("Password", validators = [DataRequired()])
    submit = SubmitField("Submit")
@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username = form.username.data).first()
        if user:
            if "password" == form.password.data:
                login_user(user)
                flash("login Succesfull")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password")
        else:
            flash("That user doesnt exist")
                
    return render_template('login.html', form = form)

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    form = LoginForm()
    return render_template('dashboard.html')

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate (app, db)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False, unique =True)
    name = db.Column(db.String(200), nullable = False)
    email = db.Column(db.String(200), nullable = False, unique = True)
    likes = db.Column(db.String(200), nullable = False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<Name %r>' % self.name

class UserForm(FlaskForm):
    name = StringField("Name ", validators = [DataRequired()])
    username = StringField("Username ", validators = [DataRequired()])
    email = StringField("Email ", validators = [DataRequired()])
    likes = StringField("Likes (Ex: Music, shopping, etc..)", validators = [DataRequired()])
    password_hash = PasswordField('Password', validators =[DataRequired(), EqualTo('password_hash2')])
    password_hash2 = PasswordField('Confirm Password', validators = [DataRequired()])
    submit = SubmitField("Submit")

@app.route('/')
def home():
    return render_template('signup.html')
@app.route('/user/add', methods = ['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit(extra_validators=None):
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(likes = form.likes.data, username = form.username.data, name = form.name.data, email = form.email.data)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ""
        form.username.data = ""
        form.likes.data = ""
        form.email.data = ""
        flash("User Added Suc")
    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form = form, name = name, our_users = our_users)

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/name', methods =['GET', 'POST'])
def name():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
    return render_template('name.html',
        name = name,
        form = form)
@app.route('/signup')
def signup():
    return render_template('signup.html')
@app.route('/home2')
def home2():
    return render_template('home2.html')


if __name__ == '__main__':
   app.run(debug=True)