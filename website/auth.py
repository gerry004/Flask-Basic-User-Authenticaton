from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', __name__)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged In Successfully", category="success")
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect Password, try again.")
        else:
            flash("User doesn't exist.", category="error")

    return render_template('login.html', user=current_user)

@auth.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')

        elif "@" not in email:
            flash("Invalid Email", category="error")
        elif len(full_name) < 2:
            flash("Invalid Full Name", category="error")
        else:
            new_user = User(email=email, password=generate_password_hash(password, method="sha256"), full_name=full_name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Account Created", category="success")
            return redirect(url_for('views.home'))

    return render_template('signup.html', user=current_user)
