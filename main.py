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
    files = db.relationship("File", backref="user", lazy=True)  # all files the user has
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
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

@app.route("/terminal", methods=['GET','POST','PUT'])
@login_required
def terminal():
    user = User.query.filter_by(username=session['username']).first()
    form=TerminalForm()
    
    if form.validate_on_submit() and user:
        status = {'response':form.text.data, 'user':user}
        response = handle_response(status)
        if response == "logout":
            return redirect(url_for('logout'))
        return render_template("terminal.html", form=form, response=response)

    return render_template("terminal.html", form=form, response="")

def handle_response(info):
    data = info['response']
    response = ""
    if data[0:3] == "cd ":
        response = change_directory(data[3:], info['user'])
    elif data[0:5] == "echo ":
        response = echo(data[5:], info['user'])
    elif data[0:6] == "touch ":
        response = touch(data[6:], info['user'])
    elif data[0:6] == "mkdir ":
        response = mkdir(data[6:], info['user'])
    elif data[0:2] == "ls":
        response = ls(data[2:], info['user'])
    elif data[0:3] == "pwd":
        response = pwd(info['user'])
    elif data[0:6] == "logout":
        response = "logout"
    return response

def change_directory(content, user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    new_folder = Folder.query.filter_by(user_id=user.id, name=content.strip()).first()

    if current_folder and new_folder:
        current_folder.current = False
        new_folder.current = True
        db.session.commit()
        return ""
    elif new_folder:
        new_folder.current = True
        db.session.commit()
        return ""
    return "Could not change directory because there is no current directory"

def echo(content, user):
    return content

def touch(content, user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()

    if current_folder:
        is_existing = File.query.filter_by(user_id=user.id, folder_id=current_folder.id, file_name=content.strip()).first()

        if not is_existing:
            new_file = File(user_id=user.id, file_name=content.strip(), created=datetime.now(), folder_id=current_folder.id)
            db.session.add(new_file)
            db.session.commit()
            return new_file.file_name

        return f'Error: file already exists in this directory with the name {content.strip()}'

    return f'Error: no current working directory'

def pwd(user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    if current_folder:
        print(current_folder.name)
        return current_folder.name

    return f'Error: no current working directory'

def mkdir(content, user):
    content = content.strip()
    is_existing = Folder.query.filter_by(user_id=user.id, name=content).first()

    if not is_existing:
        new_folder = Folder(name=content, current=False, user_id=user.id, root=False)
        db.session.add(new_folder)
        db.session.commit()
        return ""
    
    return f'Could not create {content} folder because {content} already exists'


def ls(content, user):
    # will need to keep track of current directory for this
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    if current_folder:
        files = current_folder.files
        list_files = ""
        for fil in files:
            list_files += fil.file_name
        return list_files
    return f'Could not list files in current directory because there is no current directory'


@app.route("/logout")
@login_required
def logout():
    user = session["username"]
    session.clear()
    flash(f'{user} is logged out!', 'success')
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
