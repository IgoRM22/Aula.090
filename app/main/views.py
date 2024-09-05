from flask import render_template
from flask_login import login_required
from ..models import db, User
from . import main

@main.route('/')
def index():
    users = User.query.all()

    return render_template('index.html', users=users)
