from flask import Flask, session
from flask_behind_proxy import FlaskBehindProxy
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
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
    files = db.relationship("File", backref="user", lazy=True)  # all files the user has, will remove sometime
    commands = db.relationship("Command", backref="user", lazy=True)

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
