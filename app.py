from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///service_desk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # admin, support, employee

# Модель заявки
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    responsible = db.Column(db.String(100), nullable=False)
    team = db.Column(db.String(100), nullable=False)
    theme = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), nullable=False)

# Модель услуги
class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False)

# Модель сообщения
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=True)
    sender = db.Column(db.String(100), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.String(20), nullable=False)

# Маршруты для работы с каталогом услуг
@app.route('/service_catalog', methods=['GET', 'POST'])
def service_catalog():
    services = Service.query.all()
    return render_template('service_catalog.html', services=services)

@app.route('/add_service', methods=['GET', 'POST'])
def add_service():
    if request.method == 'POST':
        new_service = Service(
            name=request.form['name'],
            description=request.form['description'],
            status=request.form['status']
        )
        db.session.add(new_service)
        db.session.commit()
        return redirect(url_for('service_catalog'))
    return render_template('add_service.html')


@app.route('/messaging_service', methods=['GET', 'POST'])
def messaging_service():
    if request.method == 'POST':
        # Логика для отправки сообщения или другая необходимая логика
        message = request.form['message']
        # Здесь вы можете добавить код для обработки и сохранения сообщения
        flash(f'Сообщение "{message}" отправлено успешно!', 'success')

    return render_template('messaging_service.html')
# Маршрут для модуля сервиса сообщений
@app.route('/messages/<int:request_id>', methods=['GET', 'POST'])
def messages(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    request_obj = Request.query.get_or_404(request_id)
    messages = Message.query.filter_by(request_id=request_id).all()
    if request.method == 'POST':
        new_message = Message(
            request_id=request_id,
            sender=session.get('username'),
            recipient=request.form['recipient'],
            content=request.form['content'],
            timestamp=datetime.datetime.now().strftime('%d.%m.%Y %H:%M')
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Сообщение отправлено!', 'success')
        return redirect(url_for('messages', request_id=request_id))
    return render_template('messages.html', request=request_obj, messages=messages)

# Маршруты для управления инцидентами Service Desk
@app.route('/incident_management', methods=['GET', 'POST'])
def incident_management():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_role = session.get('user_role')
    if user_role == 'employee':
        requests = Request.query.filter_by(responsible=session.get('username')).all()
    else:
        requests = Request.query.all()
    return render_template('incident_management.html', requests=requests)

@app.route('/add_incident', methods=['GET', 'POST'])
def add_incident():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_request = Request(
            date=datetime.datetime.now().strftime('%d.%m.%Y %H:%M'),
            status='Новая заявка',
            type=request.form['type'],
            responsible=request.form['responsible'],
            team=request.form['team'],
            theme=request.form['theme'],
            description=request.form['description']
        )
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('incident_management'))
    return render_template('add_incident.html')
@app.route('/manage_incidents', methods=['GET'])
def manage_incidents():
    if 'user_id' not in session or session.get('user_role') not in ['admin', 'support']:
        return redirect(url_for('login'))
    incidents = Request.query.all()  # Здесь предполагается, что инциденты также хранятся в таблице Request
    return render_template('manage_incidents.html', incidents=incidents)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_role = session.get('user_role')
    if user_role == 'employee':
        # Фильтруем заявки, созданные только текущим пользователем
        requests = Request.query.filter_by(responsible=session.get('username')).all()
    else:
        # Администраторы и специалисты поддержки видят все заявки
        requests = Request.query.all()
    return render_template('index.html', requests=requests)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/add_request', methods=['GET', 'POST'])
def add_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_request = Request(
            date=datetime.datetime.now().strftime('%d.%m.%Y %H:%M'),
            status='Новая',
            type=request.form['type'],
            responsible=request.form['responsible'],
            team=request.form['team'],
            theme=request.form['theme'],
            description=request.form['description']
        )
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_request.html')


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        db.session.commit()
        return redirect(url_for('view_users'))

    return render_template('edit_user.html', user=user)


@app.route('/request/<int:request_id>', methods=['GET', 'POST'])
def request_detail(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    req = Request.query.get_or_404(request_id)
    # Проверка на возможность редактирования заявки
    if request.method == 'POST' and (
            session.get('user_role') in ['admin', 'support'] or session.get('username') == req.responsible):
        req.date = request.form['date']
        req.status = request.form['status']
        req.type = request.form['type']
        req.responsible = request.form['responsible']
        req.team = request.form['team']
        req.theme = request.form['theme']
        req.description = request.form['description']
        # Сохранение изменений в базу данных
        db.session.commit()
        flash('Заявка успешно обновлена', 'success')
        return redirect(url_for('request_detail', request_id=request_id))
    return render_template('request_detail.html', request=req)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(
            username=request.form['username'],
            password=hashed_password,
            role=request.form['role']
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_user.html')

@app.route('/view_users')
def view_users():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('view_users.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)