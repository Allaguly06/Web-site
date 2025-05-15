import eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# База данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# SocketIO с eventlet
socketio = SocketIO(app, async_mode='eventlet')

# Модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

# Маршруты
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    users = User.query.filter(User.id != user.id).all()
    return render_template('index.html', user=user, users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            return "Пользователь с таким именем уже существует"

        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Неверный логин или пароль", username=username)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chat/<int:recipient_id>')
def private_chat(recipient_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    recipient = User.query.get(recipient_id)

    messages = Message.query.filter(
        ((Message.sender_id == user.id) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == user.id))
    ).order_by(Message.timestamp).all()

    return render_template('chats.html', user=user, recipient=recipient, messages=messages)

# Socket.IO обработчики
@socketio.on('join')
def on_join(data):
    room = f"{min(session['user_id'], data['recipient_id'])}_{max(session['user_id'], data['recipient_id'])}"
    join_room(room)

@socketio.on('send_private_message')
def handle_private_message(data):
    sender = User.query.get(session['user_id'])
    content = data['message'].strip()
    recipient_id = data['recipient_id']
    if not content:
        return

    message = Message(sender_id=sender.id, recipient_id=recipient_id, content=content)
    db.session.add(message)
    db.session.commit()

    room = f"{min(sender.id, recipient_id)}_{max(sender.id, recipient_id)}"
    emit('receive_private_message', {
        'username': sender.username,
        'content': content,
        'user_id': sender.id
    }, room=room)

# Инициализация базы данных
@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("База данных инициализирована.")

# Запуск
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
