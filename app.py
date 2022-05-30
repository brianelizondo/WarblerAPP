from email import message
import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
from functools import wraps
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError

from forms import UserAddForm, LoginForm, MessageForm, ProfileEditForm, EditPasswordForm
from models import Likes, db, connect_db, User, Message, Follows

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///warbler'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
toolbar = DebugToolbarExtension(app)

connect_db(app)

@app.errorhandler(404)
def page_not_found(e):
    """
    Custom 404 Error Page
    """
    do_logout()
    return render_template('404.html'), 404


def login_required(f):
    """Decorator fuction to check for is-a-user-logged-in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("Access unauthorized.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def check_private_opt(user_id, user_obj):
    if user_obj.is_private:
        show_private_opt = False
        following_users = [user.id for user in g.user.following]

        if user_id in following_users:
            check_approved = Follows.query.filter(Follows.user_being_followed_id == user_id, Follows.user_following_id == g.user.id).one_or_none()
            
            if check_approved is not None:
                if check_approved.approved:
                    show_private_opt = True
                    
    else:
        show_private_opt = True

    return show_private_opt


##############################################################################
# User signup/login/logout

@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """
    Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
                is_private=User.is_private.default.arg
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""

    # IMPLEMENT THIS
    flash("You have logout successfully", "success")
    do_logout()
    return redirect('/login')


##############################################################################
# General user routes:

@app.route('/users')
def list_users():
    """
    Page with listing of users.
    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)


@app.route('/users/<int:user_id>')
def users_show(user_id):
    """Show user profile."""

    user = User.query.get_or_404(user_id)

    # snagging messages in order from the database;
    # user.messages won't be in order by default
    messages = (Message
                .query
                .filter(Message.user_id == user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())
    
    # check if is a private user account
    # check if the user follow the private user account and if the user approved to follow
    show_private_opt = check_private_opt(user_id, user)

    return render_template('users/show.html', user=user, messages=messages, show_private_opt=show_private_opt)


@app.route('/users/<int:user_id>/following')
@login_required
def show_following(user_id):
    """Show list of people this user is following."""

    user = User.query.get_or_404(user_id)
    show_private_opt = check_private_opt(user_id, user)
    return render_template('users/following.html', user=user, show_private_opt=show_private_opt)


@app.route('/users/<int:user_id>/followers')
@login_required
def users_followers(user_id):
    """Show list of followers of this user."""

    user = User.query.get_or_404(user_id)
    show_private_opt = check_private_opt(user_id, user)
    return render_template('users/followers.html', user=user, show_private_opt=show_private_opt)


@app.route('/users/follow/<int:follow_id>', methods=['POST'])
@login_required
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""

    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()
    
    if followed_user.is_private:
        update_follow = Follows.query.filter(Follows.user_being_followed_id == follow_id, Follows.user_following_id == g.user.id).one_or_none()
        update_follow.approved = False
        db.session.add(update_follow)
        db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
@login_required
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""

    followed_user = User.query.get(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/profile', methods=["GET", "POST"])
@login_required
def profile():
    """Update profile for current user."""

    # IMPLEMENT THIS
    user = User.query.get_or_404(g.user.id)
    form = ProfileEditForm(obj=user)
    form_pass = EditPasswordForm()

    if form.validate_on_submit():
        user_check = User.authenticate(g.user.username, form.password.data)

        if user_check:
            user.username = form.username.data
            user.email = form.email.data
            user.image_url = form.image_url.data
            user.header_image_url = form.header_image_url.data
            user.bio = form.bio.data
            user.is_private = form.is_private.data
            db.session.commit()
            do_login(user)
            flash("Your profile was successfully updated", "success")
            return redirect(url_for('users_show', user_id=g.user.id))
        else:
            flash("The password is invalid", "danger")
            return redirect("/")

    return render_template('/users/edit.html', form=form, form_pass=form_pass)


@app.route('/users/profile/password', methods=["GET", "POST"])
@login_required
def update_user_password():
    """Update password for current user."""
    user = User.query.get_or_404(g.user.id)
    form = EditPasswordForm()

    if form.validate_on_submit():
        user_check = User.authenticate(g.user.username, form.current_password.data)

        if user_check:
            updated_pass = User.update_password(form.new_password.data, form.new_password_rpt.data)
            
            if updated_pass:
                user.password = updated_pass
                db.session.commit()
                flash("Your password was successfully updated", "success")
                return redirect(url_for('users_show', user_id=g.user.id))
            else:
                flash("The new password does not match", "danger")
                return redirect('/users/profile/password')
        else:
            flash("The password is invalid", "danger")
            return redirect('/users/profile/password')

    return render_template('/users/edit_pass.html', form=form)


@app.route('/users/delete', methods=["POST"])
@login_required
def delete_user():
    """Delete user."""

    do_logout()
    db.session.delete(g.user)
    db.session.commit()

    return redirect("/signup")


@app.route('/users/add_like/<int:message_id>', methods=["GET", "POST"])
@login_required
def messages_likes(message_id):
    """New feature that allows a user to 'like' a warble"""
    
    check_msg_like = Likes.query.filter(Likes.user_id == g.user.id, Likes.message_id == message_id).one_or_none()
    if check_msg_like is None:
        new_like = Likes(user_id=g.user.id, message_id=message_id)
        db.session.add(new_like)
    else:
        db.session.delete(check_msg_like)
    
    db.session.commit()
    # return redirect("/")
    return "ok"


@app.route('/users/<int:user_id>/liked_warbles')
@login_required
def users_liked_warbles(user_id):
    """Show list of liked warbles of this user."""

    user = User.query.get_or_404(user_id)
    msg_liked = [msg.id for msg in user.likes]
    messages = Message.query.filter(Message.id.in_(msg_liked)).all()

    return render_template('/users/liked_warbles.html', user=user, messages=messages)



##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
@login_required
def messages_add():
    """
    Add a message:
    Show form if GET. If valid, update message and redirect to user page.
    """

    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        # return redirect(f"/users/{g.user.id}")
        return f"/users/{g.user.id}"

    return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
def messages_show(message_id):
    """Show a message."""

    msg = Message.query.get(message_id)
    return render_template('messages/show.html', message=msg)


@app.route('/messages/<int:message_id>/delete', methods=["POST"])
@login_required
def messages_destroy(message_id):
    """Delete a message."""

    msg = Message.query.get(message_id)
    db.session.delete(msg)
    db.session.commit()

    return redirect(url_for('users_show', user_id=g.user.id))


##############################################################################
# Homepage and error pages

@app.route('/')
def homepage():
    """
    Show homepage:
    - anon users: no messages
    - logged in: 100 most recent messages of followed_users
    """

    if g.user:
        following_users = [user_follow.id for user_follow in g.user.following]
        following_users.append(g.user.id)
        messages = (Message.query.filter(Message.user_id.in_(following_users)).order_by(Message.timestamp.desc()).limit(100).all())
        msg_likes = [msg_like.message_id for msg_like in Likes.query.filter_by(user_id=g.user.id).all()]

        return render_template('home.html', messages=messages, likes=msg_likes)

    else:
        return render_template('home-anon.html')


##############################################################################
# Turn off all caching in Flask
#   (useful for dev; in production, this kind of stuff is typically
#   handled elsewhere)
#
# https://stackoverflow.com/questions/34066804/disabling-caching-in-flask

@app.after_request
def add_header(req):
    """Add non-caching headers on every request."""

    req.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    req.headers["Pragma"] = "no-cache"
    req.headers["Expires"] = "0"
    req.headers['Cache-Control'] = 'public, max-age=0'
    return req
