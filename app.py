from flask import Flask, render_template, request, session, redirect, flash, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired
from bs4 import BeautifulSoup
import requests
import secrets
from functools import wraps
from datetime import datetime
from flask_cors import CORS
from flask_socketio import leave_room
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///kunal.db"
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_NAME'] = 'ctexti'
app.config['PERMANENT_SESSION_LIFETIME'] = 86400

db = SQLAlchemy(app)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(120), nullable=False)
    fullname = db.Column(db.String(120), nullable=True)
    bio = db.Column(db.Text, nullable=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='questions', lazy=True)
    answers = db.relationship('Answer', backref='question', lazy=True)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref='answers', lazy=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)

class AnswerForm(FlaskForm):
    content = StringField('Your Answer', validators=[DataRequired()])
    submit = SubmitField('Submit Answer')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages', lazy=True)
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages', lazy=True)


class UserProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    fullname = StringField('Full Name', validators=[DataRequired()])
    bio = StringField('Bio')
    submit = SubmitField('Update Profile')

class MessageForm(FlaskForm):
    recipient = SelectField('Recipient', coerce=int, validators=[DataRequired()])
    content = StringField('Your Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

    def __init__(self, *args, **kwargs):
        super(MessageForm, self).__init__(*args, **kwargs)
        self.recipient.choices = [(user.id, user.username) for user in User.query.all()]

with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def scraper():
    url = "https://www.linkedin.com/jobs/search?keywords=Engineering&location=India&geoId=&trk=public_jobs_jobs-search-bar_search-submit&position=1&pageNum=0"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    job_cards = soup.find_all('div', class_='base-search-card')
    scraped_data = []
    for card in job_cards:
        job_element = card.find('h3', class_='base-search-card__title')
        company_element = card.find('h4', class_='base-search-card__subtitle')
        location_element = card.find('span', class_='job-search-card__location')
        time_element = card.find('time', class_='job-search-card__listdate')
        if job_element and company_element and location_element and time_element:
            job = job_element.text.strip()
            company = company_element.text.strip()
            location = location_element.text.strip()
            time = time_element.text.strip()
            job_data = {
                "job": job,
                "company": company,
                "location": location,
                "time": time
            }
            scraped_data.append(job_data)
    return scraped_data

def get_user_id():
    return session.get('user_id', None)

from flask import jsonify, request

@app.route('/get_profile_data')
@login_required
def get_profile_data():
    user_id = get_user_id()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'email': user.email,
        'fullname': user.fullname,
        'bio': user.bio,
        'this_user': user.username
    }), 200




@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user_id = get_user_id()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    user.email = data.get('email')
    user.fullname = data.get('fullname')
    user.bio = data.get('bio')

    db.session.commit()

    session['this_user'] = user.username
    session.modified = True

    return jsonify({
        'email': user.email,
        'fullname': user.fullname,
        'bio': user.bio,
        'this_user': user.username  
    }), 200

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = get_user_id()
    user = User.query.get(user_id)
    form = UserProfileForm(obj=user) 

    if request.method == 'POST' and form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash('Profile updated successfully!', 'success')

        session['this_user'] = user.username
        session.modified = True

        return redirect('/profile')

    return render_template('profile.html', this_user=session.get('this_user'), form=form)






@app.route('/answer/', methods=['POST'])
@login_required
def post_answer_default():
    current_user_id = get_user_id()
    content = request.form['content']
    if current_user_id:  
        default_question_id = 1
        new_answer = Answer(content=content, author_id=current_user_id, question_id=default_question_id)
        db.session.add(new_answer)
        db.session.commit()
        flash('Answer posted successfully!', 'success')
    else:
        flash('Please log in to post an answer.', 'error')
    return redirect('/question_and_answer')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already exists, Choose another or Login :)"
        elif not username or not password:
            error = "Username and password are required."
        elif password != confirm_password:
            error = "Passwords do not match. Please try again."
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['this_user'] = username
            flash('Logged in successfully!', 'success')
            return redirect('/dashboard')
        else:
            error = "Invalid credentials. Please try again."
            flash(error, 'error')

    return render_template('login.html', error=error)

@socketio.on('connect')
def handle_connect():
    user_id = get_user_id()
    if user_id:
        join_room(str(user_id))
        user = User.query.filter_by(id=user_id).first()
        emit('connected', {'message': 'Connected to server.', 'username': user.username})

@socketio.on('disconnect')
def handle_disconnect():
    user_id = get_user_id()
    if user_id:
        leave_room(str(user_id))
        print(f'User {user_id} disconnected.')


@app.route('/api/send_message/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    data = request.get_json()
    content = data.get('content')
    sender_id = get_user_id()
    
    if not sender_id:
        return jsonify({'error': 'Invalid sender'}), 400

    if not recipient_id:
        return jsonify({'error': 'Invalid recipient'}), 400

    if content is None or not content.strip():
        return jsonify({'error': 'Invalid message content'}), 400

    sender_username = User.query.filter_by(id=sender_id).first().username
    recipient_username = User.query.filter_by(id=recipient_id).first().username

    new_message = Message(content=content, sender_id=sender_id, recipient_id=recipient_id)
    db.session.add(new_message)
    db.session.commit()

    socketio.emit('message', {
        'sender_username': sender_username,
        'content': content,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=str(sender_id))

    socketio.emit('message', {
        'sender_username': sender_username,
        'recipient_username': recipient_username,
        'content': content,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=str(recipient_id))

    return jsonify({
        'content': content,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'sender_username': sender_username,
        'recipient_username': recipient_username  
    }), 200


@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    form = MessageForm()
    users = User.query.all()

    messages = []  

    if form.validate_on_submit():
        recipient_username = form.recipient.data
        content = form.content.data
        recipient = User.query.filter_by(username=recipient_username).first()

        if recipient:
            sender_id = get_user_id()
            new_message = Message(content=content, sender_id=sender_id, recipient_id=recipient.id)
            db.session.add(new_message)
            db.session.commit()
            socketio.emit('message', {
                'content': content,
                'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }, room=str(recipient.id))

    recipient_id = request.args.get('recipient_id')
    if recipient_id:
        messages = Message.query.filter(
            ((Message.sender_id == get_user_id()) & (Message.recipient_id == recipient_id)) |
            ((Message.sender_id == recipient_id) & (Message.recipient_id == get_user_id()))
        ).order_by(Message.timestamp).all()

    return render_template('messages.html', form=form, users=users, messages=messages)

@app.route('/api/messages/<int:recipient_id>', methods=['GET'])
@login_required
def get_messages(recipient_id):
    messages = Message.query.filter(
        ((Message.sender_id == get_user_id()) & (Message.recipient_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.recipient_id == get_user_id()))
    ).order_by(Message.timestamp).all()

    formatted_messages = [{
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'content': message.content
    } for message in messages]

    return jsonify({'messages': formatted_messages})

@app.route('/dashboard')
@login_required
def dashboard():
    scraped_job_data = scraper()
    return render_template('dashboard.html', jobs_data=scraped_job_data)

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect('/')

@app.route('/question_and_answer', methods=['GET', 'POST'])
@login_required
def question_and_answer():
    questions = Question.query.order_by(Question.timestamp.desc()).all()
    answers = Answer.query.all()
    answer_form = AnswerForm()

    default_question_content = "What are your Career Goals?"
    if not questions:
        questions.append(Question(content=default_question_content, author_id=None))

    if request.method == 'POST':
        content = request.form['content']
        current_user_id = get_user_id()
        if current_user_id:
            new_question = Question(content=content, author_id=current_user_id)
            db.session.add(new_question)
            db.session.commit()
            return redirect('/question_and_answer')
        else:
            return redirect('/login')

    return render_template('question_and_answer.html', questions=questions, answers=answers, answer_form=answer_form)

@app.route('/answer/<int:question_id>', methods=['POST'])
@login_required
def post_answer(question_id):
    current_user_id = get_user_id()
    content = request.form['content']
    if current_user_id:
        new_answer = Answer(content=content, author_id=current_user_id, question_id=question_id)
        db.session.add(new_answer)
        db.session.commit()
        flash('Answer posted successfully!', 'success')
    else:
        flash('Please log in to post an answer.', 'error')
    return redirect('/question_and_answer')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    socketio.run(app, debug=True, port=2005)
