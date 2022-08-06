from flask import Flask, render_template, url_for, flash, redirect, request, session
from flask_behind_proxy import FlaskBehindProxy
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, RegisterForm, TerminalForm
from flask_bcrypt import Bcrypt
import functools
import random
import requests
import os
import bcrypt
from datetime import datetime

app = Flask(__name__)
proxied = FlaskBehindProxy(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '0cff8064643810cf406057022287b4c5'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    folders = db.relationship("Folder", backref="user", lazy=True)  # folders in user directory
    # TODO: make a home folder initially when user is initialized
    commands = db.relationship("Command", backref="user", lazy=True)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    files = db.relationship("File", backref="folder", lazy=True)
    root = db.Column(db.Boolean, nullable=False)  # True if it is the root directory (once we figure out the parent/child rel)
    current = db.Column(db.Boolean, nullable=False)  # True if the user is currently in this directory
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), unique=True, nullable=False)
    file_content = db.Column(db.Text())
    folder_id = db.Column(db.String(255), db.ForeignKey('folder.id'),
        nullable=False)
    created = db.Column(db.DateTime())

class Command(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    text = db.Column(db.String(255), nullable=False)

def login_required(func):
    @functools.wraps(func)
    def secure_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)
    return secure_function

def is_logged_in(func):
    @functools.wraps(func)
    def secure_other(*args, **kwargs):
        if "username" in session:
            return redirect(url_for("terminal"))
        return func(*args, **kwargs)
    return secure_other

@app.route("/")
@app.route("/home")
@app.route("/homepage")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET','POST'])
@is_logged_in
def login():
    form = LoginForm()
    if form.validate_on_submit():
        existing_users_with_username = User.query.filter_by(username=form.username.data).all()
        if len(existing_users_with_username) != 0:
            user = existing_users_with_username[0]
            session["username"] = user.username
            session["email"] = user.email
            return redirect(url_for("terminal"))
        else:
            flash(f'Account does not exist for {form.username.data}. If you would like to register with this username, please click below!', 'failure')
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)

@app.route("/register", methods=['GET','POST'])
@is_logged_in
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_users_with_username = User.query.filter_by(username=form.username.data).all()
        if len(existing_users_with_username) == 0:
            pw_hash = bcrypt.generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            flash(f'Account already exists for {form.username.data}. If you would like to login with this username, please click below!', 'failure')
            return render_template("register.html", form=form)
    return render_template("register.html", form=form)

@app.route("/terminal", methods=['GET','POST'])
@login_required
def terminal():
    user = User.query.filter_by(username=session['username']).first()
    form=TerminalForm()
    
    if form.validate_on_submit() and user:
        status = {'response':form.text.data, 'user':user}
        handle_response(status)

    return render_template("terminal.html", form=form)

def handle_response(info):
    data = info['response']
    if data[0:3] == "cd ":
        change_directory(data[3:], info['user'])
    elif data[0:5] == "echo ":
        echo(data[5:], info['user'])
    elif data[0:6] == "touch ":
        touch(data[6:], info['user'])
    elif data[0:6] == "mkdir ":
        mkdir(data[6:], info['user'])
    elif data[0:2] == "ls":
        ls(data[3:], info['user'])

def change_directory(content, user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()

    if current_folder:
        current_folder.current = False
        content = content.strip()
        new_folder = Folder.query.filter_by(user_id=user.id, name=content).first()
        new_folder.current = True
        print(new_folder)

def echo(content, user):
    print(content)

def touch(content, user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()

    if current_folder:
        new_file = File(file_name=content.strip(), created=datetime.now(), folder_id=current_folder.id)
        db.session.add(new_file)
        db.session.commit()

def mkdir(content, user):
    content = content.strip()
    is_existing = Folder.query.filter_by(user_id=user.id, name=content).first()

    if not is_existing:
        new_folder = Folder(name=content, current=False, user_id=user.id, root=False)
        db.session.add(new_folder)
        db.session.commit()


def ls(content, user):
    # will need to keep track of current directory for this
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    files = current_folder.files

    for fil in files:
        print(fil.name)


@app.route("/logout")
@login_required
def logout():
    user = session["username"]
    session.clear()
    flash(f'{user} is logged out!', 'success')
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
