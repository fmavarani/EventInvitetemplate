from flask import Flask, render_template, request, redirect, url_for
from flask_mail import Mail, Message
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from flask_login import login_manager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail(app)


class User(UserMixin, db.Model):
    username = db.Column(db.String(64), primary_key=True)
    password_hash = db.Column(db.String(128), nullable=False)
    mail_server = db.Column(db.String(120), default="..")
    mail_port = db.Column(db.Integer, default=0)
    mail_use_tls = db.Column(db.Boolean, default=False)
    mail_username = db.Column(db.String(120), default="..")
    mail_password = db.Column(db.String(120), default="..")
    email_template = db.relationship(
        "EmailTemplate", backref="user", uselist=False, lazy=True
    )
    rsvp_template = db.relationship(
        "RSVPTemplate", backref="user", uselist=False, lazy=True
    )
    
    def get_id(self):
        return self.username
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class User_invitee(db.Model):
    user_id = db.Column(db.Text, db.ForeignKey("user.username"), primary_key=True)
    invitee_id = db.Column(
        db.String(120), db.ForeignKey("invitee.email"), primary_key=True
    )
    invite_link = db.Column(db.String(120), unique=True, nullable=True)
    RSVP_status = db.Column(db.Boolean, nullable=True)


class RSVPTemplate(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    template = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Text, db.ForeignKey("user.username"), nullable=True)


class Invitee(db.Model):

    email = db.Column(db.String(120), unique=True, nullable=False, primary_key=True)


class EmailTemplate(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Text, db.ForeignKey("user.username"))
    template = db.Column(db.Text, nullable=False)


def generate_invite_link(user, invitee, invite_link):
    # Send the email
    msg = Message(
        "You are invited!", sender=app.config["MAIL_USERNAME"], recipients=invitee
    )
    msg.body = user.email_template.template.replace(
        "[-invite_link-]", request.url_root + "RSPV/" + invite_link
    )
    mail.send(msg)
    db.session.commit()
    return True


@app.route("/send-invites", methods=["GET"])
@login_required
def send_invites():

    if current_user is None:
        return "User not found!", 404
    # Get the list of invitees
    invitees = (
        Invitee.query.join(User_invitee, User_invitee.c.invitee_id == Invitee.email)
        .filter(User_invitee.c.user_id == current_user.username)
        .all()
    )
    # Configure Flask-Mail
    app.config["MAIL_SERVER"] = current_user.mail_server
    app.config["MAIL_PORT"] = current_user.mail_port
    app.config["MAIL_USE_TLS"] = current_user.mail_use_tls
    app.config["MAIL_USERNAME"] = current_user.mail_username
    app.config["MAIL_PASSWORD"] = current_user.mail_password
    # Loop through the invitees
    for invitee in invitees:
        # Generate a unique invite link
        # Loop through the invitees
        if invitee.invite_link is None:
            invitee.invite_link = "".join(
                random.choices(string.ascii_letters + string.digits, k=16)
            )
            db.session.commit()
        generate_invite_link(current_user, invitee.email, invitee.invite_link)
    return render_template("home.html")


@app.route("/test-invites", methods=["GET", "POST"])
@login_required
def test_invites():

    if current_user is None:
        return "User not found!", 404
    # Configure Flask-Mail
    app.config["MAIL_SERVER"] = current_user.mail_server
    app.config["MAIL_PORT"] = current_user.mail_port
    app.config["MAIL_USE_TLS"] = current_user.mail_use_tls
    app.config["MAIL_USERNAME"] = current_user.mail_username
    app.config["MAIL_PASSWORD"] = current_user.mail_password
    generate_invite_link(
        current_user, current_user.mail_username, "invitee.invite_link"
    )
    return render_template("home.html")


@app.route("/RSVP/<invite_link>", methods=["GET", "POST"])
def rsvp(invite_link):

    # Find the invitee by the invite link
    invitee = User_invitee.query.filter_by(invite_link=invite_link).first()
    user = User.query.get(invitee.user_id)
    if invitee is None:
        return "Invalid invite link!", 404
    if request.method == "POST":
        # Update the RSVP status
        invitee.RSVP_status = request.form.get("RSVP_status")
        db.session.commit()
        return "RSVP status updated!", 200
    # Render the RSVP form
    return render_template(user.rsvp_template.template)


@login_manager.user_loader
def load_user(user_id):
    try:
        user = User.query.get(user_id)
    except Exception as e:
        # Handle the exception here
        print(f"An error occurred: {str(e)}")
        return None
    return user


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user is None or not user.check_password(request.form["password"]):
            return "Invalid username or password"
        login_user(user)
        return redirect(url_for("user_page"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():

    logout_user()
    return redirect(url_for("login"))


@app.route("/user", methods=["GET", "POST"])
@login_required
def user_page():

    if request.method == "POST":
        if "rsvp_template" in request.form:
            # Add or update the RSVP template
            if current_user.rsvp_template is None:
                rsvp_template = RSVPTemplate(template=request.form["rsvp_template"], user_id=current_user.username)
                db.session.add(rsvp_template)
            else:
                current_user.rsvp_template.template = request.form["rsvp_template"]
        if "email_template" in request.form:
            # Add or update the email template
            if current_user.email_template is None:
                email_template = EmailTemplate(template=request.form["email_template"], user_id=current_user.username)
                db.session.add(email_template)
            else:
                current_user.email_template.template = request.form["email_template"]
        db.session.commit()
    return render_template("user_page.html", user=current_user)


@app.route("/invitees", methods=["GET", "POST"])
@login_required
def manage_invitees():

    if request.method == "POST":
        if "add" in request.form:
            # Add the email to the invitee list
            email = request.form["add"]
            invitee = Invitee.query.filter_by(email=email).first()

            if invitee is None:
                invitee = Invitee(email=email)
                db.session.add(invitee)
                db.session.commit()
            # Link the user to the invitee
            user_invitee = User_invitee(
                user_id=current_user.username, invitee_id=invitee.email
            )
            db.session.add(user_invitee)
            db.session.commit()
        elif "remove" in request.form:
            # Remove the invitee from the list
            invitee_id = request.form["remove"]
            invitee = User_invitee.query.filter_by(
                user_id=current_user.username, invitee_id=invitee_id
            ).first()
            if invitee:
                db.session.delete(invitee)
                db.session.commit()
    # Get the list of invitees
    invitee = User_invitee.query.filter_by(user_id=current_user.username).all()
    return render_template("user_invitee.html", invitees=invitee)


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/edit_user", methods=["GET", "POST"])
@login_required
def edit_user():

    if current_user is None:
        return "User not found!", 404

    if request.method == "POST":
        current_user.username = request.form["username"]
        current_user.mail_server = request.form["mail_server"]
        current_user.mail_port = request.form["mail_port"]
        current_user.mail_use_tls = bool(request.form.get("mail_use_tls"))
        current_user.mail_username = request.form["mail_username"]
        current_user.mail_password = request.form["mail_password"]
        db.session.commit()
        return "User information updated!", 200

    return render_template("edit_user.html", user=current_user)


if __name__ == "__main__":

    with app.app_context():
        db.create_all()
        user =User.query.filter_by(username='admin').first()
        if user is None:
            base_user = User(username='admin')
            base_user.set_password('password')
            db.session.add(base_user)
            db.session.commit()
    app.run(debug=True)
