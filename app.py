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
    if form.is_submitted() and form.validate():
        user = Users.query.filter_by(username = form.username.data).first()
        if user:
            if "" != form.password.data:
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
    #form = LoginForm()
    form = PostForm()
    if form.is_submitted() and form.validate():
        post = Posts(tag = form.tag.data, tag2 = form.tag2.data, tag3 = form.tag3.data, title = form.title.data, content = form.content.data, author = form.author.data)
        form.title.data = ""
        form.content.data = ""
        form.author.data = ""
        form.tag.data = ""
        form.tag2.data = ""
        form.tag3.data = ""
        db.session.add(post)
        db.session.commit()
    our_posts = Posts.query.order_by(Posts.date_posted)
    return render_template('dashboard.html',form = form, our_posts = our_posts)

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
    likes2 = db.Column(db.String(200), nullable = False)
    likes3 = db.Column(db.String(200), nullable = False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    business = db.Column(db.String(20), nullable = False)
    subject = db.Column(db.String(200), nullable = True)
    content = db.Column(db.String(200), nullable = True)
    
    def __repr__(self):
        return '<Name %r>' % self.name

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(225))
    content = db.Column(db.Text)
    tag = db.Column(db.String(225))
    tag2 = db.Column(db.String(225))
    tag3 = db.Column(db.String(225))
    author = db.Column(db.String(225))
    date_posted = db.Column(db.DateTime, default = datetime.utcnow)

class PostForm(FlaskForm):
    title = StringField("Title", validators =[DataRequired()])
    content = StringField("Content", validators =[DataRequired()])
    tag = StringField("Tag 1", validators =[DataRequired()])
    tag2 = StringField("Tag 2", validators =[DataRequired()])
    tag3 = StringField("Tag 3", validators =[DataRequired()])
    author = StringField("Author", validators =[DataRequired()])
    submit = SubmitField("Submit")

@app.route('/add-post', methods = ['GET', 'POST'])
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title = form.title.data, content = form.content.data, author = form.author.data)
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''
        db.session.add(post)
        db.session.commit()
        flash("Blog post submitted")
    return render_template("add_post.html", form = form)

class UserForm(FlaskForm):
    name = StringField("Name ", validators = [DataRequired()])
    username = StringField("Username ", validators = [DataRequired()])
    email = StringField("Email ", validators = [DataRequired()])
    likes = StringField("Like 1 (Ex: Music, shopping, etc..)", validators = [DataRequired()])
    likes2 = StringField("Like 2", validators = [DataRequired()])
    likes3 = StringField("Like 3", validators = [DataRequired()])
    password_hash = PasswordField('Password', validators = [DataRequired(), EqualTo('password_hash2')])
    password_hash2 = PasswordField('Confirm Password', validators = [DataRequired()])
    business = StringField("Business/Organization? (Y/N)", validators = [DataRequired()])
    subject = StringField("Subject ")
    content = StringField("Content ")
    submit = SubmitField("Submit")

@app.route('/')
def home():
    return render_template('signup.html')
@app.route('/user/add', methods = ['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.is_submitted() and form.validate():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(likes = form.likes.data,likes2 = form.likes2.data, likes3 = form.likes3.data,  username = form.username.data, name = form.name.data, email = form.email.data, password_hash = form.password_hash.data, business = form.business.data)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ""
        form.username.data = ""
        form.likes.data = ""
        form.likes2.data = ""
        form.likes3.data = ""
        form.email.data = ""
        form.password_hash.data = ""
        form.business.data = ""
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
@login_required
def home2():
    posts = Posts.query.order_by(Posts.date_posted)

    return render_template('home2.html', posts = posts)


if __name__ == '__main__':
   app.run(debug=True)