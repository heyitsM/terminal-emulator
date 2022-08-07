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
from models import app, proxied, db, User, Folder, File, Command

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
        user = User.query.filter_by(username=form.username.data).first()
        if user:
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
        existing_users_with_username = User.query.filter_by(username=form.username.data).first()
        if not existing_users_with_username:
            pw_hash = bcrypt.generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
            home = Folder(root=True, current=True, name="~", user_id=user.id)
            db.session.add(home)
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
        response = Folder.change_directory(data[3:], info['user'])
    elif data[0:5] == "echo ":
        response = Folder.echo(data[5:], info['user'])
    elif data[0:6] == "touch ":
        response = Folder.touch(data[6:], info['user'])
    elif data[0:6] == "mkdir ":
        response = Folder.mkdir(data[6:], info['user'])
    elif data[0:2] == "ls":
        response = Folder.ls(data[2:], info['user'])
    elif data[0:3] == "pwd":
        response = Folder.pwd(info['user'])
    elif data[0:6] == "logout":
        response = "logout"
    elif data == "path":
        response = Folder.path(info['user'])
    return response

@app.route("/logout")
@login_required
def logout():
    user = session["username"]
    session.clear()
    flash(f'{user} is logged out!', 'success')
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
