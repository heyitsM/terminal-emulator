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
    home = db.Column(db.Boolean, nullable=False)
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

@app.route("/")
@app.route("/home")
@app.route("/homepage")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET','POST'])
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
def terminal():
    user = User.query.filter_by(username=session['username']).first()
    form=TerminalForm()
    if user and len(user.folders) == 0:
        home = Folder(home=False, user_id=user.id, name="base")
        db.session.add(home)
        db.session.commit()
    
    if form.validate_on_submit():
        handle_response(form.text.data)

    return render_template("terminal.html", form=form)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
