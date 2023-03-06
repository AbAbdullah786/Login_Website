from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.file import FileField, FileAllowed
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_
from datetime import datetime
import re
import os
import secrets

app = Flask(__name__, template_folder='template')
app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/registration'
db = SQLAlchemy(app)
Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    role = db.Column(db.String(255), default='user')
    date_time = db.Column(db.DateTime, default=datetime.now)
    image_file = db.Column(db.String(60))

User.parent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
User.sub_user = db.relationship('User', backref='Subordinates',
    remote_side = User.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email')])
    password = PasswordField('Password', validators=[InputRequired(), EqualTo('confirm', message='Password does not match'), Length(min=6, max=10)])
    confirm = PasswordField('Confirm', validators=[InputRequired()])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=10)])
    remember = BooleanField('remember_me')
    
class SubUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3,max=10)])
    email = StringField('email', validators=[InputRequired(), Email()])
    password = PasswordField('password', validators=[InputRequired()])
    submit = SubmitField('Create Sub_User')    

class PicForm(FlaskForm):
    pic = FileField('profile_pic', validators=[FileAllowed(['jpg','png','jpeg'])])
    submit = SubmitField('Submit')

@app.route('/')
def home():
    form = LoginForm()
    return render_template('index.html', form=form)

# Password Must be a-z, 1-9, symbol
def check_password(data):
    x = True
    while x:
        if not re.search('[a-z]',data):
            break
        elif not re.search('[0-9]',data):
            break
        elif not re.search('[@#$%^&_]',data):
            break
        else:
            x = False
            break
    return x

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        user_name = User.query.filter_by(username=username).first()
        user_email = User.query.filter_by(email=email).first()
        
        if user_name:
            flash('username alread exist')
            return render_template('signup.html', form=form)
        
        if user_email:
            flash('email already exist')
            return render_template('signup.html', form=form)
        # function call
        x = check_password(password)
        if x:
            flash('Password is wrong: At least 1 letter between [a-z], [A-Z], [0-9], [$#@]')
            return render_template('signup.html', form=form) 
        
        if not (user_name and user_email):
            new_user = User(username=username, email=email, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            
            return redirect(url_for('dashboard'))
        
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = User.query.filter_by(email=email).first()
        try:    
            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=form.remember.data)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Password is Wrong')
            else:
                flash('Invalid User')
        except:
            flash('try again')
            return render_template('login.html', form=form)
            
    return render_template('login.html', form=form)

def save_picture(form_picture):
    random_hax = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture = random_hax + f_ext
    picture_path = os.path.join(app.root_path, 'static/image', picture)
    form_picture.save(picture_path)
    return picture

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    form = PicForm()
    
    if form.validate_on_submit:
        if form.pic.data:
            picture_file = save_picture(form.pic.data)
            current_user.image_file = picture_file
            db.session.commit()
            
    return render_template('dashboard.html', form=form)

@app.route('/add_user', methods=['GET','POST'])
@login_required
def add_user():
    form = SubUserForm()
    
    if form.validate_on_submit():
        if current_user.role == 'user':
            
            user_info = User.query.filter(or_(User.username == form.username.data,
                                              User.email == form.email.data))          
            if user_info:
                for data in user_info:
                    if data.username == form.username.data:
                        flash('Username already exist')
                        return render_template('sub_user.html', form=form)
                    if data.email == form.email.data:
                        flash('email already exist')
                        return render_template('sub_user.html', form=form)
            # function call        
            x = check_password(form.password.data)
            if x:
                flash('Password is wrong: At least 1 letter between [a-z], [A-Z], [0-9], [$#@]')
                return render_template('sub_user.html', form=form)
            
            sub_user = User(
                username = form.username.data,
                email = form.email.data,
                password = generate_password_hash(form.password.data),
                role = 'sub_user',
                parent_id = current_user.id
            )
            db.session.add(sub_user)
            db.session.commit()
            return redirect(url_for('dashboard'))
        
        flash('You are sub_user and not created sub_user')    
    return render_template('sub_user.html', form=form)    

@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    return render_template('update.html', current_user=current_user)

@app.route('/update_r', methods=['GET', 'POST'])
def update_r():
    if request.method == 'POST':
        
        users = User.query.filter(User.id != current_user.id).filter(or_(User.username.like(request.form['username']),
                                                                    User.email.like(request.form['email'])))
        
        if users:
            for data in users:
                if data.username == request.form['username']:
                    flash('username alredy exist')
                    return render_template('update.html')
                if data.email == request.form['email']:
                    flash('email alredy exist')
                    return render_template('update.html')
        
        current_user.username = request.form['username']
        current_user.email = request.form['email']
        
        if request.form['old_password'] and request.form['new_password']:
           if check_password_hash(current_user.password, request.form['old_password']):
                password = request.form['new_password']
                x = check_password(password)
                if x:
                    flash('Password is wrong: At least 1 letter between [a-z], [A-Z], [0-9], [$#@]')
                    return render_template('update.html')
                current_user.password = generate_password_hash(password)
           else:
               flash('Old Password is Wrong')
               return render_template('update.html')
        
        if request.form['username'] or request.form['email'] or (request.form['old_password'] and request.form['new_password']):
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('form does not fulfill')        
    return render_template('update.html')
        
        

@app.route('/logout')
def logout():
    logout_user()
    
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)