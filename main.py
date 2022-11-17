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
import bleach
import math
from urllib.parse import quote
import re

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
    commands = db.relationship("Command", backref="user", lazy=True)
    responses = db.relationship("Prev_Response", backref="user", lazy=True)
    tokens = db.relationship("Token", backref="user", lazy=True)

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
        if "username" not in session or "email" not in session:
            return redirect(url_for("login", next=request.url))
        else:
            user = User.query.filter_by(username=session['username'], email=session['email']).first()
            if not user:
                return redirect(url_for("login", next=request.url))
        return func(*args, **kwargs)
    return secure_function

def is_logged_in(func):
    @functools.wraps(func)
    def secure_other(*args, **kwargs):
        if "username" in session and "email" in session:
            user = User.query.filter_by(username=session['username'], email=session['email']).first()
            if user:
                return redirect(url_for("terminal"))
        return func(*args, **kwargs)
    return secure_other

#ASSUMES YOU ARE LOGGED IN SO THAT MUST BE A REQUIREMENT AS WELL
def spotify_login_required(func):
    @functools.wraps(func)
    def secure_spotify(*args, **kwargs):
        user = User.query.filter_by(username=session['username'], email=session['email']).first()
        if len(list(user.tokens)) == 0:
            return redirect(url_for("spotify"))
        elif len(list(user.tokens)) == 1:
            token = list(user.tokens)[0]
            now = datetime.now()
            will_expire = now + timedelta(minutes=5)
            if token.expires_in < will_expire:
                return redirect(url_for("spotify", next=request.url))
        return func(*args, **kwargs)
    return secure_spotify

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

    secrets = Token(user_id=current_user.id, access_token=access_token, refresh_token=refresh_token, token_type=token_type, expires_in=will_expire)
    db.session.add(secrets)
    db.session.commit()
    return redirect(url_for('terminal'))

@app.route("/spotify_auth")
@login_required
def spotify():
    current_user=User.query.filter_by(username=session['username'], email=session['email']).first()
    tokens = current_user.tokens
    if len(tokens) != 0:
        Token.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

    auth_code = {
        'client_id':CLIENT_ID,
        'response_type':'code',
        'redirect_uri':'https://studiojet-samueldomain-5000.codio.io/spotify_callback/', #Change if codebox name changes or once we have it hosted on heroku
        'scope':'playlist-modify-private playlist-read-private playlist-read-collaborative playlist-modify-public ugc-image-upload',
    }

    url_args = "&".join(["{}={}".format(key, quote(val)) for key, val in auth_code.items()])
    auth_url = "{}/?{}".format(AUTH_URL, url_args)
    return redirect(auth_url)


@app.route("/terminal", methods=['GET','POST','PUT'])
@login_required
@spotify_login_required
def terminal():
    user = User.query.filter_by(username=session['username'], email=session['email']).first()
    form=TerminalForm()
    
    if form.validate_on_submit():
        status = {'response':form.text.data, 'user':user}
        response = handle_basic_response(status)

        if response == "logout":
            return redirect(url_for('logout'))
 
        if response != "cleared":
            new_command = Command(command_text=tag(user)+form.text.data, user_id=user.id)
            db.session.add(new_command)
            db.session.commit()

            if form.text.data == 'spotify login':
                return redirect(url_for('spotify'))
            elif form.text.data == 'spotify playlists':
                return redirect(url_for('terminal'))
                # return redirect(url_for('playlist_gui'))
            elif form.text.data[0:7] == "spotify":
                response = spotify_handler(user, form.text.data[7:])

            response = bleach.clean(response, tags=['a','b'])
            resp = Prev_Response(response_text=response, user_id=user.id)
            db.session.add(resp)
            db.session.commit()
            
        form.text.data=""
        commands = Command.query.order_by(Command.id.desc()).filter_by(user_id=user.id)
        responses = Prev_Response.query.order_by(Prev_Response.id.desc()).filter_by(user_id=user.id)
        return render_template("terminal.html", tag=tag(user), form=form, responses=list(responses), commands=list(commands))
    
    commands = Command.query.order_by(Command.id.desc()).filter_by(user_id=user.id)
    responses = Prev_Response.query.order_by(Prev_Response.id.desc()).filter_by(user_id=user.id)
    return render_template("terminal.html", tag=tag(user), form=form, responses=list(responses), commands=list(commands))

@app.route("/terminal/playlists", methods=['GET','POST','PUT'])
@login_required
@spotify_login_required
def playlist_gui():
    return redirect(url_for("terminal"))
    user = User.query.filter_by(username=session['username'], email=session['email']).first()
    all_playlists = list_playlists(user)

    if len(request.args.getlist("playlist")) == 0:
        return render_template("playlists.html", playlists=all_playlists)
    else:
        authorization_header = {"Authorization": f"Bearer {user.tokens[0].access_token}"}
        list_params = request.args.getlist("playlist")
        playlists = []
        ids = ""
        name = "Playlist comparison: "
        for playlist_id in list_params:
            endpoint = f"{BASE_URL}playlists/{playlist_id}"
            playlist = requests.get(endpoint, headers=authorization_header).json()
            playlists.append(playlist)
            name += playlist['name'] + ", "
            ids += playlist['id'] + ","
        name = name[:-2]
        return render_template("playlist.html", name=name, playlists=playlists, all=all_playlists, current_ids=ids)

@app.route("/terminal/playlists/add_playlist", methods=['GET','POST'])
@login_required
@spotify_login_required
def form_processing():
    new_id = request.form['playlist']
    current_ids = request.form['current_ids'].split(",")
    current_ids = [value for value in current_ids if value != "" and value != " "]
    current_ids.append(new_id)
    
    new_url = url_for('playlist_gui')+"?"
    for i in current_ids:
        new_url+="playlist="+i+"&"
    new_url = new_url[:-1]
    return redirect(new_url)

@app.route("/logout")
@login_required
def logout():
    user = session["username"]
    user = User.query.filter_by(username=user).first()
    session.clear()
    Prev_Response.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    Command.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    Token.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return redirect(url_for("home"))

def handle_basic_response(info):
    data = info['response']
    response = ""
    if data[0:6] == "logout":
        response = "logout"
    elif data == "clear":
        response = clear(info['user'])
    elif data == "help":
        response = gen_help_string()
    return response

"""
Where the merges actually happen
"""
def merge_playlists(user, data):
    authorization_header = {"Authorization": f"Bearer {user.tokens[0].access_token}"}
    playlists = list_playlists(user)

    targets = list(data.keys())
    targets.remove("new_name")
    num_targets = len(targets)
    new_list = data["new_name"]
    count_found = 0
    mergeable = []

    for target in targets:
        if type(data[target]) is list:
            to_find = data[target]
            options = []
            target_alt = target.replace("'", "’")
            for playlist in playlists:
                if target.strip() == playlist['name'].strip() or target_alt.strip() == playlist['name'].strip():
                    options.append(playlist)
            for i in to_find:
                mergeable.append(options[i - 1])
                count_found += 1
        elif type(data[target]) is int:
            for playlist in playlists:
                if target.strip() == playlist['name'].strip() or target_alt.strip() == playlist['name'].strip():
                    count_found += 1
                    mergeable.append(playlist)
                    break      
    
    if count_found >= num_targets:
        # create a new playlist with name playlist1 and playlist2 merge
        me = requests.get(BASE_URL+"me", headers=authorization_header).json()['id']
        desc = f"A merged playlist based on "

        for i in range(num_targets):
            desc += targets[i]
            if i < num_targets - 1:
                desc += " and "

        data = {"name": new_list,
                "public": False,
                "description": desc}

        created = requests.post(f"{BASE_URL}users/{me}/playlists", headers=authorization_header, data=json.dumps(data)).json()
        uris = []

        for playlist in mergeable:
            url = playlist['tracks']['href']
            resp = requests.get(url, headers=authorization_header).json()
            while resp['next'] != None:
                for item in resp['items']:
                    uris.append(item['track']['uri'])
                resp = requests.get(url, headers=authorization_header).json()
            for item in resp['items']:
                uris.append(item['track']['uri'])
        
        iterations = math.ceil(float(len(uris))/100)

        for i in range(iterations):
            if len(uris) > 100:
                data = {
                    "uris":uris[:100],
                }
                uris = uris[100:]
                adding = requests.post(created['tracks']['href'], headers=authorization_header, data=json.dumps(data)).json()
            else:
                data = {
                    "uris":uris,
                }
                adding = requests.post(created['tracks']['href'], headers=authorization_header, data=json.dumps(data)).json()
            
        return f"<a href='{created['external_urls']['spotify']}'>Link to Spotify</a>"
    else:
        return "Unable to find playlists (they are case sensitive). If this is an error on my end, don't be afraid to reach out."
    return "weird issue? you're missing error handling somewhere"

def list_playlists(user):
    authorization_header = {"Authorization": f"Bearer {user.tokens[0].access_token}"}
    to_return = list("")

    endpoint = f"{BASE_URL}me/playlists?limit={50}"
    playlists = requests.get(endpoint, headers=authorization_header).json()
    to_return += playlists['items']
    endpoint = playlists['next']

    while endpoint != None:
        playlists = requests.get(endpoint, headers=authorization_header).json()
        to_return += playlists['items']
        endpoint = playlists['next']
    
    return to_return

def list_relevant_playlists(user, data):
    all_playlists = list_playlists(user)
    relevant_playlists = []

    for playlist in all_playlists:
        if playlist['name'] == data or playlist['name'].strip() == data or playlist['name'].strip().lower() == data:
            relevant_playlists.append(playlist)
        else:
            # BELOW is to compare to any substring, will want to include later when you add more flags

            # Compares whole words in playlist name
            comparator = playlist['name'].split(" ")
            for to_comp in comparator:
                if to_comp == data:
                    relevant_playlists.append(playlist)
                    break
                    
            """
            #Will compare subwords, have to figure out how to utilize without getting repeats
            try:
                index = playlist['name'].strip().lower().index(data)
                relevant_playlists.append(playlist)
                print(playlist['name'])
                
            except ValueError:
                print("not found")
            """
            
    return relevant_playlists

def spotify_handler(user, data):
    tokens = list(user.tokens)
    token = tokens[0]
    data = data.strip()
    resp = str(token.expires_in)

    if data[0:6] == "merge ": 
        data = data[7:].strip().split("\"")
        data = format_for_merge(data)
        resp = merge_playlists(user, data)
        
    elif data[0:14] == "list playlists":
        if data[14:] == "":
            resp = list_playlists(user)
            # resp is a list
            if type(resp) is list:
                returnable = "Each playlist below is linked (click on the title to go to the playlist)\n\n"
                for i in range(len(resp)):
                    returnable += f"{i + 1}: <a href='{resp[i]['external_urls']['spotify']}'>{resp[i]['name']}</a>   "
                    if (i + 1) % 5 == 0 and i >= 4:
                        returnable += "\n\n"
                resp = returnable
        else:
            resp = data[14:].strip()
            try:
                index = data.index(" -f ")
                data = data[index + 3:].strip()
                data = data.split("\"")
                data = [i for i in data if i]
                data = [i for i in data if i.strip() != ""]

                returnable = "Each playlist below is linked (click on the title to go to the playlist)\n\n"

                for item in data:
                    one_resp = list_relevant_playlists(user, item.lower().strip())
                    if type(one_resp) is list and len(one_resp) != 0:                        
                        for i in range(len(one_resp)):
                            returnable += f"{i + 1}: <a href='{one_resp[i]['external_urls']['spotify']}'>{one_resp[i]['name']}</a>   "
                            if (i + 1) % 5 == 0 and i >= 4:
                                returnable += "\n\n"
                    else:
                        returnable += f"\n\nFor term {item}, No relevant playlists found"
                resp = returnable
            except ValueError:
                print("No -f found")
    else:
        return "invalid entry"
    return resp

def format_for_merge(inp):
    obj = {}

    for i in range(0, len(inp), 2):
        if inp[i + 1] == '' or inp[i + 1] == ' ':
            if i == len(inp) - 2:
                inp[i + 1] = 1
                obj["new_name"] = inp[i]
            else:
                inp[i + 1] = 1
                obj[inp[i]] = 1
        else:
            try:
                inp[i + 1] = int(inp[i + 1].strip())
                inp[i + 1] *= -1

                if obj.get(inp[i]) == None:
                    obj[inp[i].strip()] = [inp[i + 1]]
                else:
                    obj[inp[i]].append(inp[i + 1])
            except ValueError:
                print("Invalid Input Format")     
    return obj

def clear(user):
    Prev_Response.query.filter_by(user_id=user.id).delete()
    Command.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return "cleared"

def tag(user):
    return f"{user.username}  >"

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
