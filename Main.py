from flask import Flask, render_template, request, redirect, url_for
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    mail_server = db.Column(db.String(120), default='..')
    mail_port = db.Column(db.Integer, default=0)
    mail_use_tls = db.Column(db.Boolean, default=False)
    mail_username = db.Column(db.String(120), default='..')
    mail_password = db.Column(db.String(120), default='..')
    email_template = db.relationship('EmailTemplate', backref='user',uselist=False, lazy=True)
    rsvp_template = db.relationship('RSVPTemplate', backref='user',uselist=False, lazy=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class User_invitee (db.Model):
    user_id=db.Column( db.Integer, db.ForeignKey('user.id'), primary_key=True)
    invitee_id=db.Column( db.String(120), db.ForeignKey('invitee.email'), primary_key=True)
    invite_link=db.Column(db.String(120), unique=True, nullable=True)
    RSVP_status=db.Column(db.Boolean, nullable=True)

class RSVPTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
class Invitee(db.Model):
    email = db.Column(db.String(120), unique=True, nullable=False, primary_key=True)
    
class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    template = db.Column(db.Text, nullable=False)

mail = Mail(app)

@app.route('/send-invites', methods=['POST'])
@login_required
def send_invites():
    # Get the user
    user = current_user
    if user is None:
        return 'User not found!', 404

    # Get the list of invitees
    invitees = Invitee.query.join(User_invitee, User_invitee.c.invitee_id == Invitee.email).filter(User_invitee.c.user_id == user.id).all()

    # Configure Flask-Mail
    app.config['MAIL_SERVER'] = user.mail_server
    app.config['MAIL_PORT'] = user.mail_port
    app.config['MAIL_USE_TLS'] = user.mail_use_tls
    app.config['MAIL_USERNAME'] = user.mail_username
    app.config['MAIL_PASSWORD'] = user.mail_password

    # Loop through the invitees
    for invitee in invitees:
        # Generate a unique invite link
        invite_link = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

        # Add invite link to UserInvitee table
        invitee_link = User_invitee(user_id=user.id, invitee_id=invitee.email, invite_link=invite_link)
        db.session.add(invitee_link)

        # Send the email
        msg = Message('You are invited!',
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[invitee.email])
        msg.body = user.email_template.template.replace('[-invite_link-]', request.url_root + "RSPV/" + invite_link)
        mail.send(msg)

        db.session.commit()

    return 'Invite sent!', 200

@app.route('/RSVP/<invite_link>', methods=['GET', 'POST'])
def rsvp(invite_link):
    # Find the invitee by the invite link
    invitee = User_invitee.query.filter_by(invite_link=invite_link).first()
    user = User.query.get(invitee.user_id)
    if invitee is None:
        return 'Invalid invite link!', 404

    if request.method == 'POST':
        # Update the RSVP status
        invitee.RSVP_status = request.form.get('RSVP_status')
        db.session.commit()
        return 'RSVP status updated!', 200

    # Render the RSVP form
    return render_template(user.rsvp_template.template)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user is None or not user.check_password(request.form['password']):
            return 'Invalid username or password'
        login_user(user)
        return redirect(url_for('user_page'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/user', methods=['GET', 'POST'])
@login_required
def user_page():
    if request.method == 'POST':
        if 'rsvp_template' in request.form:
            # Add the RSVP template
            current_user.rsvp_template = request.form['rsvp_template']
        elif 'email_template' in request.form:
            # Add the email template
            current_user.email_template = request.form['email_template']
        db.session.commit()
    return render_template('user_page.html')

@app.route('/invitees', methods=['GET', 'POST'])
@login_required
def manage_invitees():
    
    if request.method == 'POST':
        if 'add' in request.form:
            # Add the email to the invitee list
            email = request.form['add']
            invitee = Invitee.query.filter_by(email=email).first()

            if invitee is None:
                invitee = Invitee(email=email)
                db.session.add(invitee)
                db.session.commit()
            # Link the user to the invitee
            user_invitee = User_invitee(user_id=current_user.id, invitee_id=invitee.email)
            db.session.add(user_invitee)
            db.session.commit()
        elif 'remove' in request.form:
            # Remove the invitee from the list
            invitee_id = request.form['remove']
            invitee = User_invitee.query.filter_by(user_id=current_user.id, invitee_id=invitee_id).first()
            if invitee:
                db.session.delete(invitee)
                db.session.commit()
    # Get the list of invitees
    invitee = User_invitee.query.filter_by(user_id=current_user.id).all()
    return render_template('user_invitee.html', invitees=invitee)
@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        base_user = User(username='admin')
        base_user.set_password('password')
        db.session.add(base_user)
        db.session.commit()
    app.run(debug=True)