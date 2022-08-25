from flask import Flask, render_template, url_for, flash, redirect, request, session, make_response
from flask_behind_proxy import FlaskBehindProxy
from flask_sqlalchemy import SQLAlchemy
from forms import LoginForm, RegisterForm, TerminalForm
from flask_bcrypt import Bcrypt
import functools
import random
import requests
from tempdb import gen_help_string
import os
import bcrypt
from datetime import datetime, timedelta
import requests
import base64
import json
from urllib.parse import quote

CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
AUTH_URL = 'https://accounts.spotify.com/authorize'
TOKEN_URL = 'https://accounts.spotify.com/api/token'
BASE_URL = 'https://api.spotify.com/v1/'

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
    files = db.relationship("File", backref="user", lazy=True)  # all files the user has, will remove sometime
    commands = db.relationship("Command", backref="user", lazy=True)
    responses = db.relationship("Prev_Response", backref="user", lazy=True)
    tokens = db.relationship("Token", backref="user", lazy=True)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    files = db.relationship("File", backref="folder", lazy=True)
    root = db.Column(db.Boolean, nullable=False)  # True if it is the root directory (once we figure out the parent/child rel)
    current = db.Column(db.Boolean, nullable=False)  # True if the user is currently in this directory
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)  # links it back to user
    
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))

    children = db.relationship('Folder',
        backref=db.backref('parent', remote_side='Folder.id'))


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
    command_text = db.Column(db.String(255), nullable=False)

class Prev_Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    response_text = db.Column(db.String(255), nullable=False)

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
        nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255), nullable=False)
    token_type = db.Column(db.String(255), nullable=False)
    expires_in = db.Column(db.DateTime(), nullable=False)

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
            return render_template("login.html", form=form, msg=f'Account does not exist for this username. If you would like to register, please click below!')
    return render_template("login.html", form=form)

@app.route("/register", methods=['GET','POST'])
@is_logged_in
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_users_with_username = User.query.filter_by(username=form.username.data).first()
        existing_users_with_email = User.query.filter_by(email=form.email.data).first()
        if not existing_users_with_username and not existing_users_with_email:
            pw_hash = bcrypt.generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()
            home = Folder(root=True, current=True, name="~", user_id=user.id)
            db.session.add(home)
            db.session.commit()
            return redirect(url_for("login"))
        else:
            if existing_users_with_email and existing_users_with_username:
                return render_template("register.html", form=form, bad_un_em=f"A user already exists with username and email you chose. If that is you, please login or recover username/password below!")
            elif existing_users_with_username:
                return render_template("register.html", form=form, bad_un=f"A user already exists with that username")
            elif existing_users_with_email:
                return render_template("register.html", form=form, bad_em=f"A user already exists with the email")
            
    return render_template("register.html", form=form)

@app.route("/spotify_callback/")
@login_required
def spotify_2():
    auth_token = request.args['code']
    payload = {
        "grant_type": "authorization_code",
        "code": str(auth_token),
        "redirect_uri": 'https://studiojet-samueldomain-5000.codio.io/spotify_callback/',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }

    post = requests.post(TOKEN_URL, data=payload)
    response_data = json.loads(post.text)

    access_token = response_data["access_token"]
    refresh_token = response_data["refresh_token"]
    token_type = response_data["token_type"]
    expires_in = response_data["expires_in"] #TODO: convert to now + time, change expires_in to expires_by for auth checking later
    now = datetime.now()
    will_expire = now + timedelta(seconds=expires_in)

    current_user=User.query.filter_by(username=session['username'], email=session['email']).first()

    if current_user:
        secrets = Token(user_id=current_user.id, access_token=access_token, refresh_token=refresh_token, token_type=token_type, expires_in=will_expire)
        db.session.add(secrets)
        db.session.commit()
        return redirect(url_for('terminal'))
    else:
        return render_template("error.html")

@app.route("/spotify_auth")
@login_required
def spotify():
    current_user=User.query.filter_by(username=session['username'], email=session['email']).first()

    if current_user:
        tokens = current_user.tokens
        if len(tokens) != 0:
            Token.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()

    auth_code = {
        'client_id':CLIENT_ID,
        'response_type':'code',
        'redirect_uri':'https://studiojet-samueldomain-5000.codio.io/spotify_callback/', #Change if codebox name changes or once we have it hosted on heroku
        'scope':'playlist-modify-private playlist-read-private',
    }

    url_args = "&".join(["{}={}".format(key, quote(val)) for key, val in auth_code.items()])
    auth_url = "{}/?{}".format(AUTH_URL, url_args)
    return redirect(auth_url)


@app.route("/terminal", methods=['GET','POST','PUT'])
@login_required
def terminal():
    user = User.query.filter_by(username=session['username'], email=session['email']).first()
    form=TerminalForm()
    
    if form.validate_on_submit() and user:
        status = {'response':form.text.data, 'user':user}
        response = handle_basic_response(status)

        if response == "logout":
            return redirect(url_for('logout'))
 
        if response != "cleared":
            new_command = Command(command_text=form.text.data, user_id=user.id)
            db.session.add(new_command)
            db.session.commit()

            if form.text.data == 'spotify login':
                return redirect(url_for('spotify'))
            elif form.text.data[0:7] == "spotify":
                if len(list(user.tokens)) == 0:
                    print("requesting another token?")
                    resp = Prev_Response(response_text="Must have auth token first, let's authenticate!", user_id=user.id)
                    db.session.add(resp)
                    db.commit()
                    return redirect(url_for("spotify"))
                elif len(list(user.tokens)) == 1:
                    token = list(user.tokens)[0]
                    now = datetime.now()
                    will_expire = now + timedelta(minutes=5)
                    if token.expires_in < will_expire:
                        print("requesting another token")
                        resp = Prev_Response(response_text="Token will soon be out of order, will re-fetch code", user_id=user.id)
                        db.session.add(resp)
                        db.commit()
                        return redirect(url_for("spotify"))
                response = spotify_handler(user, form.text.data[7:])

            resp = Prev_Response(response_text=response, user_id=user.id)
            db.session.add(resp)
            db.session.commit()
            
        form.text.data=""
        commands = Command.query.order_by(Command.id.desc()).filter_by(user_id=user.id)
        responses = Prev_Response.query.order_by(Prev_Response.id.desc()).filter_by(user_id=user.id)
        return render_template("terminal.html", form=form, responses=responses, commands=commands)
    if user:
        commands = Command.query.order_by(Command.id.desc()).filter_by(user_id=user.id)
        responses = Prev_Response.query.order_by(Prev_Response.id.desc()).filter_by(user_id=user.id)
        return render_template("terminal.html", form=form, responses=responses, commands=commands)

    return render_template("terminal.html", form=form, response="")

def handle_basic_response(info):
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
    elif data == "path":
        response = path(info['user'])
    elif data == "clear":
        response = clear(info['user'])
    elif data == "help":
        response = gen_help_string()
    return response

def merge_playlists(user, playlist1, playlist2):
    authorization_header = {"Authorization": f"Bearer {user.tokens[0].access_token}"}

    return "merged"

def list_playlists(user, num_playlists):
    try:
        num = 20
        if num_playlists != "":
            num = int(num_playlists)
        authorization_header = {"Authorization": f"Bearer {user.tokens[0].access_token}"}
        endpoint = f"{BASE_URL}me/playlists?limit={num}"
        playlists = requests.get(endpoint, headers=authorization_header).json()
        playlists = playlists['items']

        to_return = ""
        for playlist in playlists:
            to_return += f"{playlist['name']}\n"
        
        return to_return
    except ValueError:
        return "Invalid parameters. Please enter 'spotify playlists <num_playlists>"
        
    

def spotify_handler(user, data):
    tokens = list(user.tokens)
    token = tokens[0]
    data = data.strip()
    resp = token.expires_in

    if data[0:6] == "merge ":
        data = data[6:].split(" ")
        if len(data) == 2:
            resp = merge_playlists(user, data[0], data[1])
        else:
            resp="invalid num of playlists: please enter 2"
    elif data[0:9] == "playlists":
        resp = list_playlists(user, data[9:].strip())
    else:
        resp="invalid entry"
    return resp

def clear(user):
    Prev_Response.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return "cleared"

def path(user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    back = current_folder
    path = ""
    current_name = current_folder.name

    while current_name != "~":
        temp_path = path
        path = "/" + back.name + temp_path
        back = Folder.query.filter_by(user_id=user.id, id=back.parent_id).first()  # gets parent of current folder
        current_name = back.name

    return "~" + path + "/"


def change_directory(content, user):
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    new_folder = None

    if content.strip() != "..":
        new_folder = Folder.query.filter_by(user_id=user.id, name=content.strip(), parent_id=current_folder.id).first()
    else:
        parent_of_current = Folder.query.filter_by(user_id=user.id, id=current_folder.parent_id).first()  # gets parent of current for later

        if parent_of_current:
            new_folder = parent_of_current
    
    if current_folder and new_folder != None:
        current_folder.current = False
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
    current_directory = Folder.query.filter_by(user_id=user.id, current=True).first()

    content = content.strip()
    is_existing = Folder.query.filter_by(parent_id=current_directory.id, user_id=user.id, name=content).first()

    if not is_existing:
        new_folder = Folder(parent_id=current_directory.id, name=content, current=False, user_id=user.id, root=False)
        db.session.add(new_folder)
        db.session.commit()
        return ""
    
    return f'Could not create {content} folder because {content} already exists'


def ls(content, user):
    # will need to keep track of current directory for this
    current_folder = Folder.query.filter_by(user_id=user.id, current=True).first()
    # home = Folder(root=True, current=True, name="~", user_id=user.id)
    if current_folder:
        files = current_folder.files
        directories = current_folder.children

        list_files = ""
        for fil in files:
            list_files += fil.file_name +" "
        for dire in directories:
            list_files += f'<b>{dire.name}</b>' + " "
        return list_files

    return f'Could not list files in current directory because there is no current directory'


@app.route("/logout")
@login_required
def logout():
    user = session["username"]
    # full_user = User.query.filter_by(username=session['username'], email=session['email']).first().tokens.delete()
    # db.session.commit()
    session.clear()
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
