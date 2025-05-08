from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import os
import signal
import shutil
from dotenv import load_dotenv
from datetime import datetime
import secrets
import string
from functools import wraps
import subprocess
import uuid
import tempfile
import psutil
import json

concurrent_path = os.path.dirname(__file__)
os.chdir(concurrent_path)
load_dotenv()

# Список запрещенных модулей и функций
FORBIDDEN_IMPORTS = {
    'os', 'sys', 'subprocess', 'shutil', 'socket', 'requests',
    'urllib', 'http', 'ftp', 'telnetlib', 'smtplib', 
    'paramiko', 'pickle', 'shelve', 'glob', 'webbrowser'
}

FORBIDDEN_FUNCTIONS = {
    'eval', 'exec', 'compile', '__import__', 'open', 
    'input', 'raw_input', 'breakpoint', 'globals', 'locals'
}

def check_code_safety(code):
    """Проверяет код на наличие потенциально опасных конструкций"""
    import ast
    
    try:
        # Парсим код в AST
        tree = ast.parse(code)
        
        # Проверяем импорты и вызовы функций
        for node in ast.walk(tree):
            # Проверка импортов
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for name in node.names:
                    module = name.name.split('.')[0]
                    if module in FORBIDDEN_IMPORTS:
                        return False, f"Использование модуля '{module}' запрещено"
            
            # Проверка вызовов функций
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in FORBIDDEN_FUNCTIONS:
                        return False, f"Использование функции '{node.func.id}' запрещено"
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in FORBIDDEN_FUNCTIONS:
                        return False, f"Использование функции '{node.func.attr}' запрещено"
        
        # Проверяем общий размер кода
        if len(code) > 10000:  # Ограничение в 10KB
            return False, "Код превышает максимально допустимый размер"
            
        return True, "Код безопасен"
        
    except SyntaxError:
        return False, "Синтаксическая ошибка в коде"
    except Exception as e:
        return False, f"Ошибка при проверке кода: {str(e)}"

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_teacher() or current_user.is_super_admin()):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

    # Связи с пользователями
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class UserRating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    
    # Поля для отслеживания прогресса по блокам
    theory_completed = db.Column(db.Boolean, default=False)
    test_completed = db.Column(db.Boolean, default=False)
    practice_completed = db.Column(db.Boolean, default=False)
    
    # Связи с другими моделями
    lesson = db.relationship('Lesson', backref=db.backref('user_progress', lazy=True))
    completed_tasks = db.relationship('PracticeTask', secondary='user_completed_tasks',
                                    backref=db.backref('completed_by', lazy=True))

# Таблица для связи многие-ко-многим между UserProgress и PracticeTask
user_completed_tasks = db.Table('user_completed_tasks',
    db.Column('progress_id', db.Integer, db.ForeignKey('user_progress.id'), primary_key=True),
    db.Column('task_id', db.Integer, db.ForeignKey('practice_task.id'), primary_key=True),
    db.Column('completed_at', db.DateTime, default=db.func.now())
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    user_type = db.Column(db.String(20), default='student')  # student, teacher, admin
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # ID пользователя, создавшего этого пользователя
    created_at = db.Column(db.DateTime, default=db.func.now())
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Связи с другими моделями
    progress = db.relationship('UserProgress', backref='user', lazy=True)
    ratings = db.relationship('UserRating', backref='user', lazy=True)
    created_users = db.relationship('User', backref=db.backref('creator', remote_side=[id]))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_teacher(self):
        return self.user_type == 'teacher'

    def is_student(self):
        return self.user_type == 'student'

    def is_super_admin(self):
        return self.is_admin and self.user_type == 'admin'

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.Integer, unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    # Теоретический материал
    theory_content = db.Column(db.Text)
    
    # Тест по теории
    theory_test = db.relationship('TheoryTest', backref='lesson', uselist=False)
    
    # Практические задачи
    practice_tasks = db.relationship('PracticeTask', backref='lesson', lazy=True)
    
    # ID предыдущего урока, который нужно пройти
    required_lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=True)
    
    # Связь с предыдущим уроком
    required_lesson = db.relationship('Lesson', remote_side=[id], backref='next_lessons')

class TheoryTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    max_score = db.Column(db.Integer, default=100)
    time_limit = db.Column(db.Integer)  # Время на прохождение в минутах
    questions = db.relationship('TestQuestion', backref='test', lazy=True)
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    is_active = db.Column(db.Boolean, default=True)
    required_score = db.Column(db.Integer, default=70)  # Минимальный балл для прохождения

class TestQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('theory_test.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)  # single_choice, multiple_choice, text
    correct_answer = db.Column(db.String(200), nullable=False)
    options = db.Column(db.JSON)  # Список вариантов ответов
    points = db.Column(db.Integer, default=1)  # Баллы за правильный ответ
    explanation = db.Column(db.Text)  # Объяснение правильного ответа
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

class PracticeTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    function_name = db.Column(db.String(200), nullable=False)  # Название функции
    initial_code = db.Column(db.Text)  # Начальный код для задачи
    order_number = db.Column(db.Integer, nullable=False)
    is_required = db.Column(db.Boolean, default=False)
    tests = db.relationship('TaskTest', backref='task', lazy=True, cascade='all, delete-orphan', passive_deletes=True)

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('theory_test.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    is_passed = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime, nullable=False)
    completed_at = db.Column(db.DateTime)
    answers = db.Column(db.JSON)  # Хранение ответов пользователя
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    user = db.relationship('User', backref=db.backref('test_results', lazy=True))
    test = db.relationship('TheoryTest', backref=db.backref('results', lazy=True))
    lesson = db.relationship('Lesson', backref=db.backref('test_results', lazy=True))

class TaskTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('practice_task.id'), nullable=False)
    function = db.Column(db.String(200), nullable=False)  # Название функции для теста
    input_data = db.Column(db.Text, nullable=False)  # Аргументы функции
    expected_output = db.Column(db.Text, nullable=False)
    is_hidden = db.Column(db.Boolean, default=False)
    order_number = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<TaskTest {self.id}>'

class Solution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('practice_task.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

class SolutionComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solution_id = db.Column(db.Integer, db.ForeignKey('solution.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Добавляем отношение к модели User
    admin = db.relationship('User', backref=db.backref('solution_comments', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('student_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Поиск пользователя без учета регистра
        user = User.query.filter(db.func.lower(User.username) == db.func.lower(username)).first()
        
        if not user or not user.check_password(password):
            flash('Неверный логин или пароль')
            return redirect(url_for('login'))
            
        if not user.is_active:
            flash('Аккаунт заблокирован')
            return redirect(url_for('login'))
            
        login_user(user, remember=remember)
        user.last_login = db.func.now()
        db.session.commit()
        
        return redirect(url_for('student_dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    # Получаем все уроки
    lessons = Lesson.query.order_by(Lesson.order_number).all()
    
    # Получаем прогресс пользователя
    user_progress = UserProgress.query.filter_by(user_id=current_user.id).all()
    completed_lesson_ids = [progress.lesson_id for progress in user_progress if progress.is_completed]
    
    # Подготавливаем данные для отображения
    lesson_data = []
    for i, lesson in enumerate(lessons):
        # Первый урок всегда доступен
        if i == 0:
            can_access = True
        else:
            # Проверяем, пройден ли предыдущий урок
            previous_lesson = lessons[i-1]
            can_access = previous_lesson.id in completed_lesson_ids
        
        lesson_data.append({
            'id': lesson.id,
            'title': lesson.title,
            'description': lesson.description,
            'can_access': can_access,
            'required_lesson_id': lesson.required_lesson_id if i > 0 else None
        })
    
    # Рассчитываем прогресс
    total_lessons = len(lessons)
    completed_lessons = len(completed_lesson_ids)
    progress_percentage = int((completed_lessons / total_lessons * 100)) if total_lessons > 0 else 0
    
    return render_template('student/dashboard.html',
                         lessons=lesson_data,
                         progress_percentage=progress_percentage,
                         completed_lessons=completed_lessons,
                         total_lessons=total_lessons,
                         completed_lesson_ids=completed_lesson_ids)

@app.route('/chat')
@login_required
def chat():
    # Для студентов показываем чат с их учителем
    if current_user.is_student():
        teacher = User.query.get(current_user.created_by)
        if not teacher:
            flash('У вас нет назначенного учителя', 'warning')
            return redirect(url_for('student_dashboard'))
        
        # Получаем сообщения
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == teacher.id)) |
            ((ChatMessage.sender_id == teacher.id) & (ChatMessage.receiver_id == current_user.id))
        ).order_by(ChatMessage.created_at).all()
        
        # Помечаем сообщения как прочитанные
        for message in messages:
            if message.receiver_id == current_user.id and not message.is_read:
                message.is_read = True
        db.session.commit()
        
        return render_template('chat.html', 
                             messages=messages, 
                             teacher=teacher,
                             is_student=True)
    
    # Для учителей показываем список их студентов
    elif current_user.is_teacher():
        students = User.query.filter_by(created_by=current_user.id, user_type='student').all()
        # Для каждого студента считаем количество непрочитанных сообщений
        students_with_unread = []
        for student in students:
            unread_count = ChatMessage.query.filter_by(
                sender_id=student.id,
                receiver_id=current_user.id,
                is_read=False
            ).count()
            students_with_unread.append({
                'id': student.id,
                'name': student.name,
                'email': student.email,
                'unread_count': unread_count
            })
        return render_template('chat.html', 
                             students=students_with_unread,
                             is_student=False)
    
    return redirect(url_for('index'))

@app.route('/chat/<int:student_id>')
@login_required
@teacher_required
def chat_with_student(student_id):
    student = User.query.get_or_404(student_id)
    
    # Проверяем, что студент действительно создан текущим учителем
    if student.created_by != current_user.id:
        abort(403)
    
    # Получаем сообщения
    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == student.id)) |
        ((ChatMessage.sender_id == student.id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.created_at).all()
    
    # Помечаем сообщения как прочитанные
    for message in messages:
        if message.receiver_id == current_user.id and not message.is_read:
            message.is_read = True
    db.session.commit()
    
    return render_template('chat.html', 
                         messages=messages, 
                         student=student,
                         is_student=False)

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        # Присоединяем пользователя к его персональной комнате
        join_room(f'user_{current_user.id}')
        if current_user.is_student():
            # Студенты также присоединяются к комнате своего учителя
            teacher = User.query.get(current_user.created_by)
            if teacher:
                join_room(f'user_{teacher.id}')
        elif current_user.is_teacher():
            # Учителя присоединяются к комнатам своих студентов
            students = User.query.filter_by(created_by=current_user.id, user_type='student').all()
            for student in students:
                join_room(f'user_{student.id}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')
    
    if not receiver_id or not message_text:
        return
    
    receiver = User.query.get_or_404(receiver_id)
    
    # Проверяем права на отправку сообщения
    if current_user.is_student():
        if receiver.id != current_user.created_by:
            return
    elif current_user.is_teacher():
        if receiver.created_by != current_user.id:
            return
    
    # Создаем новое сообщение
    message = ChatMessage(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        message=message_text
    )
    
    db.session.add(message)
    db.session.commit()
    
    # Отправляем сообщение получателю
    emit('new_message', {
        'id': message.id,
        'sender_id': message.sender_id,
        'receiver_id': message.receiver_id,
        'message': message.message,
        'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': message.is_read
    }, room=f'user_{receiver.id}')

@socketio.on('mark_as_read')
def handle_mark_as_read(message_id):
    if not current_user.is_authenticated:
        return
    
    message = ChatMessage.query.get_or_404(message_id)
    if message.receiver_id != current_user.id:
        return
    
    message.is_read = True
    db.session.commit()

@app.route('/student/lesson/<int:lesson_id>')
@login_required
def view_student_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    if not lesson.is_active:
        flash('Этот урок не доступен')
        return redirect(url_for('student_dashboard'))
        
    # Первый урок всегда доступен, если активен
    if lesson.order_number == 1:
        pass
    else:
        # Проверяем все предыдущие уроки
        previous_lessons = Lesson.query.filter(
            Lesson.order_number < lesson.order_number,
            Lesson.is_active == True
        ).order_by(Lesson.order_number).all()
        
        for prev_lesson in previous_lessons:
            prev_progress = UserProgress.query.filter_by(
                user_id=current_user.id,
                lesson_id=prev_lesson.id
            ).first()
            
            if not prev_progress or not prev_progress.is_completed:
                flash(f'Сначала необходимо пройти урок "{prev_lesson.title}"')
                return redirect(url_for('student_dashboard'))
    
    # Получаем прогресс пользователя по текущему уроку
    progress = UserProgress.query.filter_by(
        user_id=current_user.id,
        lesson_id=lesson_id
    ).first()
    
    if not progress:
        progress = UserProgress(
            user_id=current_user.id,
            lesson_id=lesson_id,
            is_completed=False
        )
        db.session.add(progress)
    
    # Проверяем, пройден ли тест
    test = TheoryTest.query.filter_by(lesson_id=lesson_id, is_active=True).first()
    test_result = None
    if test:
        # Получаем все попытки прохождения теста
        test_results = TestResult.query.filter_by(
            user_id=current_user.id,
            test_id=test.id
        ).order_by(TestResult.created_at.desc()).all()
        
        # Проверяем, есть ли успешная попытка
        test_result = next((result for result in test_results if result.is_passed), None)
    
    # Практика доступна только если тест пройден успешно
    practice_available = test_result is not None
    
    # Рассчитываем прогресс по блокам
    total_blocks = 3  # теория, тест, практика
    completed_blocks = 0
    
    # Проверяем прогресс по каждому блоку
    if progress.theory_completed:
        completed_blocks += 1
    if progress.test_completed:
        completed_blocks += 1
    
    # Проверяем прогресс по практическим задачам
    if practice_available:
        # Получаем все обязательные задачи
        mandatory_tasks = PracticeTask.query.filter_by(lesson_id=lesson_id, is_required=True).all()
        total_mandatory = len(mandatory_tasks)
        
        if total_mandatory > 0:
            # Получаем все решенные задачи пользователя
            solved_tasks = Solution.query.join(PracticeTask).filter(
                Solution.user_id == current_user.id,
                Solution.is_correct == True,
                PracticeTask.lesson_id == lesson_id,
                PracticeTask.is_required == True
            ).with_entities(Solution.task_id).all()
            
            solved_task_ids = [task_id for (task_id,) in solved_tasks]
            solved_mandatory = sum(1 for task in mandatory_tasks if task.id in solved_task_ids)
            
            # Если все обязательные задачи решены, считаем практику пройденной
            if solved_mandatory == total_mandatory:
                progress.practice_completed = True
                completed_blocks += 1
            else:
                progress.practice_completed = False
        else:
            # Если нет обязательных задач, считаем практику пройденной
            progress.practice_completed = True
            completed_blocks += 1
    
    # Обновляем статус завершения урока
    if completed_blocks == total_blocks:
        progress.is_completed = True
        progress.completed_at = datetime.now()
    else:
        progress.is_completed = False
        progress.completed_at = None
    
    db.session.commit()
    
    progress_percentage = int((completed_blocks / total_blocks * 100))
    
    return render_template('student/lesson.html',
                         lesson=lesson,
                         progress=progress,
                         progress_percentage=progress_percentage,
                         completed_blocks=completed_blocks,
                         total_blocks=total_blocks,
                         practice_available=practice_available)

@app.route('/student/lesson/<int:lesson_id>/theory')
@login_required
def view_lesson_theory(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    if not lesson.is_active:
        flash('Этот урок не доступен')
        return redirect(url_for('student_dashboard'))
    
    # Получаем прогресс пользователя
    progress = UserProgress.query.filter_by(
        user_id=current_user.id,
        lesson_id=lesson_id
    ).first()
    
    if not progress:
        progress = UserProgress(
            user_id=current_user.id,
            lesson_id=lesson_id,
            is_completed=False
        )
        db.session.add(progress)
        db.session.commit()
    
    return render_template('student/theory.html', lesson=lesson, progress=progress)

@app.route('/student/lesson/<int:lesson_id>/practice')
@login_required
def view_practice_tasks(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    if not lesson.is_active:
        flash('Этот урок еще не опубликован.', 'warning')
        return redirect(url_for('student_dashboard'))
    
    # Получаем все обязательные задачи для урока
    mandatory_tasks = PracticeTask.query.filter_by(lesson_id=lesson_id, is_required=True).all()
    
    # Получаем все дополнительные задачи для урока
    optional_tasks = PracticeTask.query.filter_by(lesson_id=lesson_id, is_required=False).all()
    
    # Получаем все решенные задачи пользователя для текущего урока
    solved_tasks = Solution.query.join(PracticeTask).filter(
        Solution.user_id == current_user.id,
        Solution.is_correct == True,
        PracticeTask.lesson_id == lesson_id
    ).with_entities(Solution.task_id).all()
    
    # Преобразуем в список ID решенных задач
    solved_task_ids = [task_id for (task_id,) in solved_tasks]
    
    # Рассчитываем прогресс выполнения обязательных задач
    total_mandatory = len(mandatory_tasks)
    solved_mandatory = sum(1 for task in mandatory_tasks if task.id in solved_task_ids)
    progress_percentage = round((solved_mandatory / total_mandatory * 100) if total_mandatory > 0 else 0)
    
    return render_template('student/practice.html',
                         lesson=lesson,
                         mandatory_tasks=mandatory_tasks,
                         optional_tasks=optional_tasks,
                         completed_task_ids=solved_task_ids,
                         progress_percentage=progress_percentage,
                         solved_mandatory=solved_mandatory,
                         total_mandatory=total_mandatory)

@app.route('/student/lesson/<int:lesson_id>/practice/task/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_practice_task(lesson_id, task_id):
    progress = UserProgress.query.filter_by(
        user_id=current_user.id,
        lesson_id=lesson_id
    ).first_or_404()
    
    task = PracticeTask.query.get_or_404(task_id)
    
    if task not in progress.completed_tasks:
        progress.completed_tasks.append(task)
        db.session.commit()
        flash('Задача отмечена как выполненная!', 'success')
    
    return redirect(url_for('view_practice_tasks', lesson_id=lesson_id))

@app.route('/student/lesson/<int:lesson_id>/practice/task/<int:task_id>')
@login_required
def view_practice_task(lesson_id, task_id):
    task = PracticeTask.query.get_or_404(task_id)
    lesson = Lesson.query.get_or_404(lesson_id)
    
    # Получаем последнее решение пользователя для этой задачи
    last_solution = Solution.query.filter_by(
        user_id=current_user.id,
        task_id=task_id
    ).order_by(Solution.created_at.desc()).first()
    
    # Получаем комментарии к последнему решению
    comments = []
    if last_solution:
        comments = SolutionComment.query.filter_by(
            solution_id=last_solution.id
        ).order_by(SolutionComment.created_at.desc()).all()
    
    # Используем код последнего решения или начальный код задачи
    initial_code = last_solution.code if last_solution else task.initial_code
    
    return render_template('student/practice_task.html', 
                         task=task, 
                         lesson=lesson,
                         user_code=initial_code,
                         comments=comments)

def create_superadmin():
    """Создание супер-администратора при первом запуске"""
    # Проверяем, существует ли уже супер-админ
    superadmin = User.query.filter_by(user_type='admin', is_admin=True).first()
    if not superadmin:
        # Создаем супер-админа
        superadmin = User(
            name='Администратор',
            email='admin@example.com',
            username='admin',
            is_admin=True,
            user_type='admin',
            is_active=True
        )
        superadmin.set_password('admin123')  # В реальном приложении используйте более сложный пароль
        db.session.add(superadmin)
        db.session.commit()
        print('Супер-админ создан')

def create_teacher():
    """Создание преподавателя при первом запуске"""
    # Проверяем, существует ли уже преподаватель
    teacher = User.query.filter_by(user_type='teacher').first()
    if not teacher:
        # Создаем преподавателя
        teacher = User(
            name='Преподаватель',
            email='teacher@example.com',
            username='teacher',
            is_admin=True,
            user_type='teacher',
            is_active=True
        )

        teacher.set_password('teacher123')  # В реальном приложении используйте более сложный пароль
        db.session.add(teacher)
        db.session.commit()
        print('Преподаватель создан')

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)  # Запрет доступа для не-админов
        
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Проверяем права доступа
    if not current_user.is_super_admin() and user.created_by != current_user.id:
        abort(403)
    
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Проверка уникальности имени пользователя
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Пользователь с таким логином уже существует', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
            
        # Проверка уникальности email
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
            
        user.name = name
        user.username = username
        user.email = email
        
        # Обновление типа пользователя (только для администратора)
        if current_user.is_super_admin():
            new_user_type = request.form.get('user_type')
            if new_user_type and new_user_type != user.user_type:
                # Проверяем, не пытаемся ли изменить тип супер-админа
                if user.is_super_admin():
                    flash('Нельзя изменить тип супер-администратора', 'danger')
                    return redirect(url_for('edit_user', user_id=user_id))
                user.user_type = new_user_type
                user.is_admin = (new_user_type != 'student')
        
        # Обновление пароля, если он был указан
        if password:
            user.set_password(password)
        
        db.session.commit()
        flash('Данные пользователя успешно обновлены', 'success')
        return redirect(url_for('user_list'))
        
    return render_template('edit_user.html', 
                         user=user,
                         can_edit_type=current_user.is_super_admin())

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        abort(403)
        
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'активирован' if user.is_active else 'деактивирован'
    flash(f'Пользователь {user.username} {status}', 'success')
    return redirect(url_for('user_list'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Проверяем права доступа:
    # - Супер-админ может удалять любых пользователей
    # - Учитель может удалять только созданных им студентов
    if not current_user.is_super_admin() and (user.created_by != current_user.id or user.user_type != 'student'):
        abort(403)
    
    # Удаляем все связанные данные пользователя
    # 1. Удаляем прогресс по урокам
    UserProgress.query.filter_by(user_id=user_id).delete()
    
    # 2. Удаляем результаты тестов
    TestResult.query.filter_by(user_id=user_id).delete()
    
    # 3. Удаляем решения практических задач и связанные комментарии
    solutions = Solution.query.filter_by(user_id=user_id).all()
    for solution in solutions:
        # Удаляем комментарии к решению
        SolutionComment.query.filter_by(solution_id=solution.id).delete()
        # Удаляем само решение
        db.session.delete(solution)
    
    # 4. Удаляем комментарии, оставленные пользователем (если он был администратором)
    SolutionComment.query.filter_by(admin_id=user_id).delete()
    
    # 5. Удаляем самого пользователя
    db.session.delete(user)
    
    try:
        db.session.commit()
        flash('Пользователь и все связанные с ним данные успешно удалены.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Произошла ошибка при удалении пользователя.', 'danger')
        app.logger.error(f'Ошибка при удалении пользователя {user_id}: {str(e)}')
    
    return redirect(url_for('user_list'))

@app.route('/admin/users')
@login_required
@teacher_required
def user_list():
    # Если текущий пользователь - супер-админ, показываем всех пользователей
    if current_user.is_super_admin():
        users = User.query.all()
    else:
        # Если текущий пользователь - преподаватель, показываем только его студентов
        users = User.query.filter_by(created_by=current_user.id).all()
    
    return render_template('user_list.html', users=users)

def generate_secure_password(length=12):
    """Генерация безопасного пароля из букв и цифр"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@teacher_required
def add_user():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Проверка существования пользователя
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким логином уже существует', 'danger')
            return redirect(url_for('add_user'))
        
        # Определяем тип пользователя
        if current_user.is_super_admin():
            user_type = request.form.get('user_type', 'student')  # Администратор может выбрать тип
        else:
            user_type = 'student'  # Преподаватели могут создавать только студентов
        
        # Проверка на создание учителя
        if user_type == 'teacher' and not current_user.is_super_admin():
            flash('Только администратор может создавать учителей', 'danger')
            return redirect(url_for('add_user'))
        
        # Создание нового пользователя
        new_user = User(
            name=name,
            username=username,
            email=f"{username}@example.com",
            is_active=True,
            is_admin=(user_type != 'student'),  # Учителя и администраторы имеют права админа
            user_type=user_type,
            created_by=current_user.id
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Пользователь {name} успешно создан', 'success')
        return redirect(url_for('user_list'))
    
    # Генерация начального пароля
    initial_password = generate_secure_password()
    
    # Передаем возможность выбора типа пользователя в шаблон
    can_create_teachers = current_user.is_super_admin()
    
    return render_template('add_user.html', 
                         initial_password=initial_password,
                         can_create_teachers=can_create_teachers)

@app.route('/admin/lessons')
@login_required
@teacher_required
def lesson_list():
    # Если пользователь не супер-администратор, перенаправляем в личный кабинет
    if not current_user.is_super_admin():
        flash('Доступ к управлению уроками имеет только администратор', 'warning')
        return redirect(url_for('student_dashboard'))
    
    lessons = Lesson.query.order_by(Lesson.order_number).all()
    return render_template('lesson_list.html', lessons=lessons)

@app.route('/admin/lessons/create', methods=['GET', 'POST'])
@login_required
@teacher_required
def create_lesson():
    # Если пользователь не супер-администратор, перенаправляем в личный кабинет
    if not current_user.is_super_admin():
        flash('Доступ к управлению уроками имеет только администратор', 'warning')
        return redirect(url_for('student_dashboard'))
    
    if request.method == 'POST':
        try:
            order_number = request.form.get('order_number')
            title = request.form.get('title')
            description = request.form.get('description')
            
            # Проверка на пустые поля
            if not order_number or not title:
                flash('Пожалуйста, заполните все обязательные поля', 'danger')
                return render_template('create_lesson.html', 
                                    order_number=order_number,
                                    title=title,
                                    description=description)
            
            # Проверка существования урока с таким номером
            if Lesson.query.filter_by(order_number=order_number).first():
                flash('Урок с таким номером уже существует', 'danger')
                return render_template('create_lesson.html', 
                                    order_number=order_number,
                                    title=title,
                                    description=description)
            
            # Создание нового урока
            new_lesson = Lesson(
                order_number=order_number,
                title=title,
                description=description,
                is_active=True
            )
            
            db.session.add(new_lesson)
            db.session.commit()
            
            flash(f'Урок "{title}" успешно создан', 'success')
            return redirect(url_for('lesson_list'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Произошла ошибка при создании урока: {str(e)}', 'danger')
            return render_template('create_lesson.html',
                                order_number=order_number,
                                title=title,
                                description=description)
    
    return render_template('create_lesson.html')

@app.route('/admin/lessons/<int:lesson_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_lesson(lesson_id):
    if not current_user.is_super_admin():
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        try:
            # Получаем данные из формы
            order_number = request.form.get('order_number')
            title = request.form.get('title')
            description = request.form.get('description', '').strip()
            is_active = request.form.get('is_active') == 'on'
            
            # Проверка существования урока с таким номером
            existing_lesson = Lesson.query.filter_by(order_number=order_number).first()
            if existing_lesson and existing_lesson.id != lesson.id:
                flash('Урок с таким номером уже существует', 'danger')
                return redirect(url_for('edit_lesson', lesson_id=lesson.id))
            
            # Обновляем данные урока
            lesson.order_number = order_number
            lesson.title = title
            lesson.description = description if description else None
            lesson.is_active = is_active
            
            # Сохраняем изменения в базе данных
            db.session.commit()
            
            flash('Урок успешно обновлен', 'success')
            return redirect(url_for('view_lesson', lesson_id=lesson.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Произошла ошибка при обновлении урока: {str(e)}', 'danger')
            return redirect(url_for('edit_lesson', lesson_id=lesson.id))
    
    return render_template('edit_lesson.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/toggle', methods=['POST'])
@login_required
def toggle_lesson_status(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    lesson.is_active = not lesson.is_active
    db.session.commit()
    
    flash(f'Урок {"активирован" if lesson.is_active else "деактивирован"}', 'success')
    return redirect(url_for('lesson_list'))

@app.route('/admin/lessons/<int:lesson_id>/delete', methods=['POST'])
@login_required
def delete_lesson(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    try:
        lesson = Lesson.query.get_or_404(lesson_id)
        
        # Проверяем, является ли урок обязательным для других уроков
        if lesson.next_lessons:
            flash('Невозможно удалить урок, так как он является обязательным для других уроков', 'danger')
            return redirect(url_for('lesson_list'))
        
        # Удаляем связанные данные в правильном порядке
        
        # 1. Удаляем прогресс пользователей
        UserProgress.query.filter_by(lesson_id=lesson_id).delete()
        
        # 2. Удаляем результаты тестов
        TestResult.query.filter_by(lesson_id=lesson_id).delete()
        
        # 3. Удаляем тест по теории и его вопросы
        if lesson.theory_test:
            # Сначала удаляем все вопросы теста
            TestQuestion.query.filter_by(test_id=lesson.theory_test.id).delete()
            # Затем удаляем сам тест
            db.session.delete(lesson.theory_test)
        
        # 4. Удаляем практические задачи и их тесты
        # Получаем все задачи урока
        tasks = PracticeTask.query.filter_by(lesson_id=lesson_id).all()
        for task in tasks:
            # Удаляем все тесты задачи
            TaskTest.query.filter_by(task_id=task.id).delete()
            # Удаляем решения задач
            Solution.query.filter_by(task_id=task.id).delete()
            # Удаляем комментарии к решениям
            SolutionComment.query.filter(SolutionComment.solution_id.in_(
                db.session.query(Solution.id).filter_by(task_id=task.id)
            )).delete()
            # Удаляем саму задачу
            db.session.delete(task)
        
        # 5. Удаляем сам урок
        db.session.delete(lesson)
        
        # Сохраняем изменения
        db.session.commit()
        
        flash('Урок и все связанные с ним данные успешно удалены', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении урока: {str(e)}', 'danger')
        app.logger.error(f'Ошибка при удалении урока {lesson_id}: {str(e)}')
    
    return redirect(url_for('lesson_list'))

@app.route('/admin/lessons/<int:lesson_id>')
@login_required
@teacher_required
def view_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    return render_template('view_lesson.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/theory/add', methods=['GET', 'POST'])
@login_required
def add_theory(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        content = request.form.get('content')
        lesson.theory_content = content
        db.session.commit()
        flash('Теоретический материал успешно добавлен', 'success')
        return redirect(url_for('view_lesson', lesson_id=lesson.id))
    
    return render_template('add_theory.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/theory/edit', methods=['GET', 'POST'])
@login_required
def edit_theory(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        content = request.form.get('content')
        lesson.theory_content = content
        db.session.commit()
        flash('Теоретический материал успешно обновлен', 'success')
        return redirect(url_for('view_lesson', lesson_id=lesson.id))
    
    return render_template('edit_theory.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/test/add', methods=['GET', 'POST'])
@login_required
def add_theory_test(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        max_score = int(request.form.get('max_score', 100))
        time_limit = int(request.form.get('time_limit', 0))
        required_score = int(request.form.get('required_score', 70))
        
        test = TheoryTest(
            lesson_id=lesson_id,
            title=title,
            description=description,
            max_score=max_score,
            time_limit=time_limit,
            required_score=required_score
        )
        
        db.session.add(test)
        db.session.commit()
        
        flash('Тест успешно создан')
        return redirect(url_for('edit_theory_test', lesson_id=lesson_id))
    
    return render_template('add_theory_test.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/test/edit', methods=['GET', 'POST'])
@login_required
def edit_theory_test(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    
    if not test:
        return redirect(url_for('add_theory_test', lesson_id=lesson_id))
    
    if request.method == 'POST':
        test.title = request.form.get('title')
        test.description = request.form.get('description')
        test.max_score = int(request.form.get('max_score', 100))
        test.time_limit = int(request.form.get('time_limit', 0))
        test.required_score = int(request.form.get('required_score', 70))
        test.is_active = bool(request.form.get('is_active'))
        
        db.session.commit()
        flash('Тест успешно обновлен')
        return redirect(url_for('edit_theory_test', lesson_id=lesson_id))
    
    return render_template('edit_theory_test.html', lesson=lesson, test=test)

@app.route('/admin/lessons/<int:lesson_id>/test/questions/add', methods=['GET', 'POST'])
@login_required
def add_test_question(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    
    if not test:
        flash('Сначала создайте тест')
        return redirect(url_for('add_theory_test', lesson_id=lesson_id))
    
    if request.method == 'POST':
        question_text = request.form.get('question_text')
        question_type = request.form.get('question_type')
        correct_answer = request.form.get('correct_answer')
        points = int(request.form.get('points', 1))
        explanation = request.form.get('explanation')
        
        options = []
        if question_type in ['single_choice', 'multiple_choice']:
            options = request.form.getlist('options[]')
        
        question = TestQuestion(
            test_id=test.id,
            question_text=question_text,
            question_type=question_type,
            correct_answer=correct_answer,
            options=options,
            points=points,
            explanation=explanation
        )
        
        db.session.add(question)
        db.session.commit()
        
        flash('Вопрос успешно добавлен')
        return redirect(url_for('edit_theory_test', lesson_id=lesson_id))
    
    return render_template('add_test_question.html', lesson=lesson, test=test)

@app.route('/admin/lessons/<int:lesson_id>/test/questions/<int:question_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_test_question(lesson_id, question_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    question = TestQuestion.query.get_or_404(question_id)
    
    if request.method == 'POST':
        question.question_text = request.form.get('question_text')
        question.question_type = request.form.get('question_type')
        question.correct_answer = request.form.get('correct_answer')
        question.points = int(request.form.get('points', 1))
        question.explanation = request.form.get('explanation')
        
        if question.question_type in ['single_choice', 'multiple_choice']:
            question.options = request.form.getlist('options[]')
        
        db.session.commit()
        flash('Вопрос успешно обновлен')
        return redirect(url_for('edit_theory_test', lesson_id=lesson_id))
    
    return render_template('edit_test_question.html', lesson=lesson, test=test, question=question)

@app.route('/admin/lessons/<int:lesson_id>/test/questions/<int:question_id>/delete', methods=['POST'])
@login_required
def delete_test_question(lesson_id, question_id):
    if not current_user.is_admin:
        abort(403)
    
    question = TestQuestion.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    
    flash('Вопрос успешно удален')
    return redirect(url_for('edit_theory_test', lesson_id=lesson_id))

@app.route('/admin/lessons/<int:lesson_id>/practice/add', methods=['GET', 'POST'])
@login_required
def add_practice_task(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        try:
            # Получаем данные из формы
            title = request.form.get('title')
            description = request.form.get('description')
            function_name = request.form.get('function_name')
            initial_code = request.form.get('initial_code')
            order_number = int(request.form.get('order_number'))
            is_required = 'is_required' in request.form
            
            # Проверяем обязательные поля
            if not function_name:
                flash('Необходимо указать имя функции', 'danger')
                return render_template('add_practice_task.html', lesson=lesson)
            
            # Создаем задачу
            task = PracticeTask(
                lesson_id=lesson.id,
                title=title,
                description=description,
                function_name=function_name,
                initial_code=initial_code,
                order_number=order_number,
                is_required=is_required
            )
            db.session.add(task)
            db.session.commit()
            
            flash('Задача успешно добавлена', 'success')
            return redirect(url_for('edit_practice_tasks', lesson_id=lesson.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении задачи: {str(e)}', 'danger')
    
    return render_template('add_practice_task.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/tasks/edit', methods=['GET', 'POST'])
@login_required
def edit_practice_tasks(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        # Обработка обновления задач
        pass
    
    return render_template('edit_practice_tasks.html', lesson=lesson)

@app.route('/admin/lessons/<int:lesson_id>/description', methods=['POST'])
@login_required
def update_lesson_description(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    description = request.form.get('description', '').strip()
    
    lesson.description = description if description else None
    db.session.commit()
    
    flash('Описание урока успешно обновлено', 'success')
    return redirect(url_for('view_lesson', lesson_id=lesson.id))

@app.route('/lessons/<int:lesson_id>/test', methods=['GET', 'POST'])
@login_required
def take_test(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id, is_active=True).first()
    
    if not test:
        flash('Тест не найден или неактивен')
        return redirect(url_for('view_student_lesson', lesson_id=lesson_id))
    
    # Проверяем, пройдена ли теория
    progress = UserProgress.query.filter_by(
        user_id=current_user.id,
        lesson_id=lesson_id
    ).first()
    
    if not progress or not progress.theory_completed:
        flash('Сначала необходимо пройти теоретический материал')
        return redirect(url_for('view_lesson_theory', lesson_id=lesson_id))
    
    # Получаем все попытки прохождения теста
    previous_results = TestResult.query.filter_by(
        user_id=current_user.id,
        test_id=test.id
    ).order_by(TestResult.created_at.desc()).all()
    
    # Если есть успешная попытка и это GET запрос, показываем результаты
    if request.method == 'GET' and any(result.is_passed for result in previous_results):
        # Проверяем, хочет ли пользователь пройти тест снова
        if request.args.get('retake') == 'true':
            return render_template('take_test.html', lesson=lesson, test=test)
        return render_template('test_results.html', 
                            lesson=lesson, 
                            test=test, 
                            results=previous_results)
    
    if request.method == 'POST':
        try:
            # Создаем новую попытку прохождения теста
            result = TestResult(
                user_id=current_user.id,
                lesson_id=lesson_id,
                test_id=test.id,
                started_at=datetime.now(),
                answers={}
            )
            
            # Проверяем время выполнения теста
            if test.time_limit:
                time_elapsed = (datetime.now() - result.started_at).total_seconds() / 60
                if time_elapsed > test.time_limit:
                    flash(f'Время на прохождение теста истекло. Лимит: {test.time_limit} минут', 'danger')
                    return redirect(url_for('test_results', lesson_id=lesson_id))
            
            total_score = 0
            max_possible_score = 0
            
            for question in test.questions:
                max_possible_score += question.points
                answer_key = f'answer_{question.id}'
                
                if question.question_type == 'single_choice':
                    answer = request.form.get(answer_key)
                    if answer is None:
                        continue
                    result.answers[str(question.id)] = answer
                    if answer == question.correct_answer:
                        total_score += question.points
                        
                elif question.question_type == 'multiple_choice':
                    # Получаем все выбранные значения для множественного выбора
                    answers = request.form.getlist(f'{answer_key}[]')
                    if not answers:
                        continue
                    result.answers[str(question.id)] = answers
                    
                    # Сравниваем множества выбранных и правильных ответов
                    try:
                        correct_answers = json.loads(question.correct_answer)
                        if isinstance(correct_answers, list):
                            if set(answers) == set(correct_answers):
                                total_score += question.points
                    except json.JSONDecodeError:
                        # Если не удалось распарсить JSON, используем старый метод
                        correct_answers = set(question.correct_answer.split(','))
                        user_answers = set(answers)
                        if correct_answers == user_answers:
                            total_score += question.points
                        
                elif question.question_type == 'text':
                    answer = request.form.get(answer_key, '').strip().lower()
                    if not answer:
                        continue
                    result.answers[str(question.id)] = answer
                    correct_answer = question.correct_answer.strip().lower()
                    
                    # Более гибкое сравнение для текстовых ответов
                    if answer == correct_answer:
                        total_score += question.points
                    else:
                        # Проверяем частичное совпадение (например, для числовых ответов)
                        try:
                            if float(answer) == float(correct_answer):
                                total_score += question.points
                        except ValueError:
                            pass
            
            # Вычисляем процент правильных ответов
            percentage_score = (total_score / max_possible_score * 100) if max_possible_score > 0 else 0
            result.score = round(percentage_score)
            result.is_passed = percentage_score >= test.required_score
            result.completed_at = datetime.now()
            
            db.session.add(result)
            
            # Обновляем прогресс пользователя
            if result.is_passed:
                progress.test_completed = True
                # Проверяем, все ли блоки пройдены
                if progress.theory_completed and progress.test_completed:
                    progress.is_completed = True
                    progress.completed_at = datetime.now()
                flash(f'Поздравляем! Вы успешно прошли тест. Ваш результат: {result.score} баллов', 'success')
                db.session.commit()
                return redirect(url_for('view_practice_tasks', lesson_id=lesson_id))
            else:
                flash(f'К сожалению, вы не прошли тест. Ваш результат: {result.score} баллов. Необходимо набрать минимум {test.required_score} баллов', 'danger')
                db.session.commit()
                return redirect(url_for('test_results', lesson_id=lesson_id))
                
        except Exception as e:
            db.session.rollback()
            flash(f'Произошла ошибка при проверке теста: {str(e)}', 'danger')
            return redirect(url_for('test_results', lesson_id=lesson_id))
    
    return render_template('take_test.html', lesson=lesson, test=test)

@app.route('/lessons/<int:lesson_id>/test/results')
@login_required
def test_results(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    
    if not test:
        flash('Тест не найден')
        return redirect(url_for('view_student_lesson', lesson_id=lesson_id))
    
    results = TestResult.query.filter_by(
        user_id=current_user.id,
        test_id=test.id
    ).order_by(TestResult.created_at.desc()).all()
    
    return render_template('test_results.html', lesson=lesson, test=test, results=results)

@app.route('/admin/task-tests/add', methods=['POST'])
@login_required
def add_task_test():
    task_id = request.form.get('task_id')
    input_data = request.form.get('input_data')
    expected_output = request.form.get('expected_output')
    is_hidden = 'is_hidden' in request.form
    
    task = PracticeTask.query.get_or_404(task_id)
    
    # Определяем порядковый номер для нового теста
    last_test = TaskTest.query.filter_by(task_id=task_id).order_by(TaskTest.order_number.desc()).first()
    order_number = (last_test.order_number + 1) if last_test else 1
    
    test = TaskTest(
        task_id=task_id,
        function=task.function_name,  # Используем имя функции из задачи
        input_data=input_data,
        expected_output=expected_output,
        is_hidden=is_hidden,
        order_number=order_number
    )
    
    db.session.add(test)
    db.session.commit()
    
    flash('Тест успешно добавлен', 'success')
    return redirect(url_for('edit_practice_tasks', lesson_id=task.lesson_id))

@app.route('/admin/task-tests/<int:test_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_task_test(test_id):
    test = TaskTest.query.get_or_404(test_id)
    task = test.task
    lesson_id = task.lesson_id
    
    db.session.delete(test)
    db.session.commit()
    
    flash('Тест успешно удален', 'success')
    return redirect(url_for('edit_practice_tasks', lesson_id=lesson_id))

@app.route('/admin/practice-tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_practice_task(task_id):
    task = PracticeTask.query.get_or_404(task_id)
    
    if request.method == 'POST':
        task.title = request.form.get('title')
        task.description = request.form.get('description')
        task.function_name = request.form.get('function_name')
        task.initial_code = request.form.get('initial_code')
        task.order_number = int(request.form.get('order_number'))
        task.is_required = 'is_required' in request.form
        
        db.session.commit()
        flash('Задача успешно обновлена', 'success')
        return redirect(url_for('edit_practice_tasks', lesson_id=task.lesson_id))
    
    return render_template('edit_practice_task.html', task=task)

@app.route('/admin/task-tests/upload', methods=['POST'])
@login_required
@admin_required
def upload_task_tests():
    if 'file' not in request.files:
        flash('Файл не выбран', 'danger')
        return redirect(request.referrer or url_for('index'))
        
    file = request.files['file']
    task_id = request.form.get('task_id')
    
    if not file or not task_id:
        flash('Необходимо выбрать файл и указать ID задачи', 'danger')
        return redirect(request.referrer or url_for('index'))
        
    if not file.filename.endswith('.json'):
        flash('Поддерживаются только JSON файлы (.json)', 'danger')
        return redirect(request.referrer or url_for('index'))
        
    task = PracticeTask.query.get_or_404(task_id)
    
    try:
        content = file.read().decode('utf-8')
        tests = parse_test_file(content)
        
        for test_data in tests:
            test = TaskTest(
                task_id=task_id,
                function=task.function_name,  # Используем имя функции из задачи
                input_data=test_data['input_data'],
                expected_output=test_data['expected_output'],
                is_hidden=test_data['is_hidden'],
                order_number=test_data['order_number']
            )
            db.session.add(test)
            
        db.session.commit()
        flash(f'Успешно добавлено {len(tests)} тестов', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обработке файла: {str(e)}', 'danger')
        
    return redirect(url_for('edit_practice_tasks', lesson_id=task.lesson_id))

def parse_test_file(content):
    """
    Парсит JSON-файл с тестами для практической задачи.
    Формат файла:
    {
        "tests": [
            {
                "input": [1, 2, 3],  # Список аргументов
                "output": 6,         # Ожидаемый результат
                "is_hidden": false,  # Скрытый тест или нет
                "order": 1           # Порядковый номер
            },
            {
                "input": ["hello", "world"],
                "output": "helloworld",
                "is_hidden": true,
                "order": 2
            }
        ]
    }
    """
    try:
        data = json.loads(content)
        if not isinstance(data, dict) or 'tests' not in data:
            raise ValueError("Неверный формат файла. Ожидается объект с полем 'tests'")
            
        tests = []
        for test in data['tests']:
            if not all(key in test for key in ['input', 'output', 'order']):
                raise ValueError("Каждый тест должен содержать поля 'input', 'output' и 'order'")
                
            # Преобразуем входные данные в строку для хранения в БД
            input_str = json.dumps(test['input'])
            output_str = json.dumps(test['output'])
            
            tests.append({
                'input_data': input_str,
                'expected_output': output_str,
                'is_hidden': test.get('is_hidden', False),
                'order_number': test['order']
            })
            
        return tests
    except json.JSONDecodeError as e:
        raise ValueError(f"Ошибка парсинга JSON: {str(e)}")
    except Exception as e:
        raise ValueError(f"Ошибка при обработке файла: {str(e)}")

def next_line(content, current_line):
    lines = content.split('\n')
    current_index = lines.index(current_line)
    if current_index + 1 < len(lines):
        return lines[current_index + 1].strip()
    return ''

@app.route('/tasks/<int:task_id>/solve', methods=['GET', 'POST'])
@login_required
def solve_task(task_id):
    task = PracticeTask.query.get_or_404(task_id)
    
    # Получаем последнее решение пользователя для этой задачи
    last_solution = Solution.query.filter_by(
        user_id=current_user.id,
        task_id=task_id
    ).order_by(Solution.created_at.desc()).first()
    
    if request.method == 'POST':
        user_code = request.form.get('code')
        results = []
        
        for test in task.tests:
            try:
                # Создаем временный файл с кодом пользователя
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                    temp_file.write(user_code)
                    temp_file_path = temp_file.name
                
                # Создаем строку для вызова функции с аргументами
                function_call = f"print({task.function_name}({test.input_data}))"
                
                # Запускаем код с тестовыми данными
                process = subprocess.Popen(
                    ['python', '-c', f"{user_code}\n{function_call}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Получаем результат
                stdout, stderr = process.communicate()
                
                # Проверяем результат
                is_correct = stdout.strip() == test.expected_output.strip()
                error = stderr if stderr else None
                
                results.append({
                    'test_number': test.order_number,
                    'arguments': test.input_data,
                    'expected': test.expected_output,
                    'actual': stdout.strip(),
                    'is_correct': is_correct,
                    'error': error,
                    'is_hidden': test.is_hidden
                })
                
            except Exception as e:
                results.append({
                    'test_number': test.order_number,
                    'arguments': test.input_data,
                    'expected': test.expected_output,
                    'actual': None,
                    'is_correct': False,
                    'error': str(e),
                    'is_hidden': test.is_hidden
                })
            
            finally:
                # Удаляем временный файл
                os.remove(temp_file_path)
        
        # Проверяем, все ли тесты пройдены
        all_tests_passed = all(r['is_correct'] for r in results)
        
        # Сохраняем решение
        solution = Solution(
            user_id=current_user.id,
            task_id=task_id,
            code=user_code,
            is_correct=all_tests_passed
        )
        db.session.add(solution)
        db.session.commit()
        
        return render_template('solve_task.html', 
                             task=task, 
                             results=results,
                             all_tests_passed=all_tests_passed,
                             user_code=user_code)
    
    # Для GET запроса показываем последнее решение или начальный код
    initial_code = last_solution.code if last_solution else task.initial_code
    return render_template('solve_task.html', task=task, user_code=initial_code)

@app.route('/admin/practice-tasks/<int:task_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_practice_task(task_id):
    task = PracticeTask.query.get_or_404(task_id)
    lesson_id = task.lesson_id
    
    try:
        db.session.delete(task)
        db.session.commit()
        flash('Задача успешно удалена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении задачи: {str(e)}', 'danger')
    
    return redirect(url_for('edit_practice_tasks', lesson_id=lesson_id))

@app.route('/api/run-tests', methods=['POST'])
@login_required
def run_tests():
    data = request.get_json()
    code = data.get('code')
    task_id = data.get('task_id')
    
    task = PracticeTask.query.get_or_404(task_id)
    results = []
    
    for test in task.tests:
        try:
            # Создаем временный файл с кодом пользователя
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            # Парсим входные данные из JSON
            input_data = json.loads(test.input_data)
            
            # Создаем строку для вызова функции с аргументами
            if isinstance(input_data, list):
                # Если входные данные - список, распаковываем его в аргументы
                args_str = ', '.join(repr(arg) for arg in input_data)
                function_call = f"print({test.function}({args_str}))"
            else:
                # Если входные данные - один аргумент
                function_call = f"print({test.function}({repr(input_data)}))"
            
            # Запускаем код с тестовыми данными
            process = subprocess.Popen(
                ['python', '-c', f"{code}\n{function_call}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Получаем результат
            stdout, stderr = process.communicate(timeout=5)  # 5 секунд
            
            # Парсим ожидаемый результат из JSON
            expected_output = json.loads(test.expected_output)
            
            # Парсим полученный результат
            try:
                actual_output = json.loads(stdout.strip())
            except json.JSONDecodeError:
                actual_output = stdout.strip()
            
            # Сравниваем результаты
            is_correct = actual_output == expected_output
            error = stderr if stderr else None
            
            results.append({
                'name': f'Тест {test.order_number}',
                'passed': is_correct,
                'function': test.function,
                'arguments': input_data,
                'expected': expected_output,
                'actual': actual_output,
                'error': error
            })
            
        except subprocess.TimeoutExpired:
            results.append({
                'name': f'Тест {test.order_number}',
                'passed': False,
                'function': test.function,
                'arguments': input_data,
                'expected': expected_output,
                'actual': None,
                'error': 'Превышено время выполнения (5 секунд)'
            })
        except Exception as e:
            results.append({
                'name': f'Тест {test.order_number}',
                'passed': False,
                'function': test.function,
                'arguments': input_data,
                'expected': expected_output,
                'actual': None,
                'error': str(e)
            })
    
    return jsonify({'tests': results})

@app.route('/api/submit-solution', methods=['POST'])
@login_required
def submit_solution():
    data = request.get_json()
    code = data.get('code')
    task_id = data.get('task_id')
    
    task = PracticeTask.query.get_or_404(task_id)
    lesson_id = task.lesson_id
    
    # Проверяем все тесты
    all_tests_passed = True
    for test in task.tests:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            function_call = f"print({task.function_name}({test.input_data}))"
            
            process = subprocess.Popen(
                ['python', '-c', f"{code}\n{function_call}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if stdout.strip() != test.expected_output.strip() or stderr:
                all_tests_passed = False
                break
                
        finally:
            os.remove(temp_file_path)
    
    # Сохраняем решение
    solution = Solution(
        user_id=current_user.id,
        task_id=task_id,
        code=code,
        is_correct=all_tests_passed
    )
    db.session.add(solution)
    db.session.commit()
    
    return jsonify({'success': True})

def run_tests(code, task_id):
    try:
        # Создаем временную директорию для этого запуска
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, f'test_{uuid.uuid4()}.py')
        
        # Записываем код в файл
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(code)
        
        # Получаем тесты для задачи
        task = PracticeTask.query.get(task_id)
        if not task:
            return {'success': False, 'error': 'Задача не найдена'}
        
        test_cases = task.test_cases
        results = []
        
        # Запускаем каждый тест
        for test in test_cases:
            try:
                # Создаем временный файл для каждого теста
                test_file = os.path.join(temp_dir, f'test_{uuid.uuid4()}.py')
                with open(test_file, 'w', encoding='utf-8') as f:
                    f.write(code + '\n\n' + test['test_code'])
                
                # Запускаем тест с ограничением времени (5 секунд) и памяти (1 МБ)
                process = subprocess.Popen(
                    ['python', test_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                try:
                    # Мониторинг использования памяти
                    memory_limit = 1024 * 1024  # 1 МБ в байтах
                    memory_exceeded = False
                    
                    while process.poll() is None:
                        try:
                            process_info = psutil.Process(process.pid)
                            memory_usage = process_info.memory_info().rss
                            
                            if memory_usage > memory_limit:
                                memory_exceeded = True
                                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            break
                    
                    if memory_exceeded:
                        results.append({
                            'name': test['name'],
                            'passed': False,
                            'function': test['function'],
                            'arguments': test['arguments'],
                            'expected': test['expected'],
                            'error': 'Превышен лимит памяти (1 МБ)',
                            'memory_exceeded': True
                        })
                        continue
                    
                    stdout, stderr = process.communicate(timeout=5)  # 5 секунд
                    
                    # Проверяем результат
                    if process.returncode == 0:
                        results.append({
                            'name': test['name'],
                            'passed': True,
                            'function': test['function'],
                            'arguments': test['arguments'],
                            'expected': test['expected'],
                            'actual': stdout.strip()
                        })
                    else:
                        results.append({
                            'name': test['name'],
                            'passed': False,
                            'function': test['function'],
                            'arguments': test['arguments'],
                            'expected': test['expected'],
                            'actual': stdout.strip(),
                            'error': stderr.strip()
                        })
                        
                except subprocess.TimeoutExpired:
                    process.kill()
                    results.append({
                        'name': test['name'],
                        'passed': False,
                        'function': test['function'],
                        'arguments': test['arguments'],
                        'expected': test['expected'],
                        'error': 'Превышено время выполнения теста (5 секунд)',
                        'timeout': True
                    })
                
                # Удаляем временный файл теста
                os.remove(test_file)
                
            except Exception as e:
                results.append({
                    'name': test['name'],
                    'passed': False,
                    'function': test['function'],
                    'arguments': test['arguments'],
                    'expected': test['expected'],
                    'error': str(e)
                })
        
        # Удаляем временные файлы и директорию
        try:
            os.remove(temp_file)
            os.rmdir(temp_dir)
        except:
            pass
        
        return {'success': True, 'tests': results}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

@app.route('/admin/user/<int:user_id>/lessons')
@login_required
def view_user_lessons(user_id):
    if not current_user.is_admin:
        abort(403)
        
    user = User.query.get_or_404(user_id)
    
    # Получаем все уроки
    lessons = Lesson.query.order_by(Lesson.order_number).all()
    
    # Получаем прогресс пользователя
    user_progress = UserProgress.query.filter_by(user_id=user_id).all()
    completed_lesson_ids = [progress.lesson_id for progress in user_progress if progress.is_completed]
    
    # Рассчитываем прогресс
    total_lessons = len(lessons)
    completed_lessons = len(completed_lesson_ids)
    progress_percentage = int((completed_lessons / total_lessons * 100)) if total_lessons > 0 else 0
    
    return render_template('user_lessons.html',
                         user=user,
                         lessons=lessons,
                         completed_lesson_ids=completed_lesson_ids,
                         progress_percentage=progress_percentage,
                         completed_lessons=completed_lessons,
                         total_lessons=total_lessons)

@app.route('/admin/user/<int:user_id>/lesson/<int:lesson_id>')
@login_required
def view_user_lesson_details(user_id, lesson_id):
    if not current_user.is_admin:
        abort(403)
        
    user = User.query.get_or_404(user_id)
    lesson = Lesson.query.get_or_404(lesson_id)
    
    # Получаем прогресс пользователя по уроку
    progress = UserProgress.query.filter_by(
        user_id=user_id,
        lesson_id=lesson_id
    ).first()
    
    if not progress:
        progress = UserProgress(
            user_id=user_id,
            lesson_id=lesson_id,
            is_completed=False,
            theory_completed=False,
            test_completed=False,
            practice_completed=False
        )
    
    # Получаем результаты тестов
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    test_results = []
    if test:
        test_results = TestResult.query.filter_by(
            user_id=user_id,
            test_id=test.id
        ).order_by(TestResult.created_at.desc()).all()
    
    # Получаем практические задачи
    practice_tasks = PracticeTask.query.filter_by(lesson_id=lesson_id).all()
    
    # Получаем список решенных задач и их решения
    solved_tasks = Solution.query.filter_by(
        user_id=user_id,
        is_correct=True
    ).with_entities(Solution.task_id).all()
    completed_task_ids = [task_id for (task_id,) in solved_tasks]
    
    # Добавляем решения к задачам
    for task in practice_tasks:
        task.solutions = Solution.query.filter_by(
            user_id=user_id,
            task_id=task.id,
            is_correct=True
        ).order_by(Solution.created_at.desc()).all()
        
        # Загружаем комментарии для каждого решения
        for solution in task.solutions:
            solution.comments = SolutionComment.query.filter_by(
                solution_id=solution.id
            ).order_by(SolutionComment.created_at.asc()).all()
    
    return render_template('user_lesson_details.html',
                         user=user,
                         lesson=lesson,
                         progress=progress,
                         test_results=test_results,
                         practice_tasks=practice_tasks,
                         completed_task_ids=completed_task_ids)

@app.route('/admin/solution/<int:solution_id>/comment', methods=['POST'])
@login_required
@teacher_required
def add_solution_comment(solution_id):
    solution = Solution.query.get_or_404(solution_id)
    task = PracticeTask.query.get_or_404(solution.task_id)
    comment_text = request.form.get('comment')
    
    if not comment_text:
        flash('Комментарий не может быть пустым', 'error')
        return redirect(url_for('view_user_lesson_details', 
                              user_id=solution.user_id, 
                              lesson_id=task.lesson_id))
    
    comment = SolutionComment(
        solution_id=solution_id,
        admin_id=current_user.id,
        comment=comment_text
    )
    
    db.session.add(comment)
    db.session.commit()
    
    # Отправка сообщения в чат студенту с ссылкой на задачу
    task_url = url_for('view_practice_task', lesson_id=task.lesson_id, task_id=task.id, _external=True)
    chat_message = ChatMessage(
        sender_id=current_user.id,
        receiver_id=solution.user_id,
        message=f'Ваше решение задачи прокомментировано: {comment_text}\nПосмотреть задачу: {task_url}',
        created_at=datetime.now(),
        is_read=False
    )
    db.session.add(chat_message)
    db.session.commit()
    
    flash('Комментарий добавлен', 'success')
    return redirect(url_for('view_user_lesson_details', 
                          user_id=solution.user_id, 
                          lesson_id=task.lesson_id))

@app.route('/student/lesson/<int:lesson_id>/theory/complete', methods=['POST'])
@login_required
def complete_theory(lesson_id):
    # Получаем прогресс пользователя
    progress = UserProgress.query.filter_by(
        user_id=current_user.id,
        lesson_id=lesson_id
    ).first()
    
    if not progress:
        progress = UserProgress(
            user_id=current_user.id,
            lesson_id=lesson_id
        )
        db.session.add(progress)
    
    # Отмечаем теорию как пройденную
    progress.theory_completed = True
    db.session.commit()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    with app.app_context():
        # Создаем таблицы, если они не существуют
        db.create_all()
        # Создаем супер-админа, если его нет
        create_superadmin()
        # Создаем преподавателя, если его нет
        create_teacher()
    socketio.run(app,host='0.0.0.0', port=8080)