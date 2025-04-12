from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from datetime import datetime
import secrets
import string
from functools import wraps
import subprocess

load_dotenv()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    function_name = db.Column(db.String(200), nullable=False)  # Название функции
    initial_code = db.Column(db.Text)  # Начальный код для задачи
    order_number = db.Column(db.Integer, nullable=False)
    is_required = db.Column(db.Boolean, default=False)
    tests = db.relationship('TaskTest', backref='task', lazy=True, cascade='all, delete-orphan')

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        if password != password_confirm:
            flash('Пароли не совпадают')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует')
            return redirect(url_for('register'))
            
        user = User(
            name=name,
            email=email,
            username=username,
            is_active=True,
            is_admin=False
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь вы можете войти.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Неверный логин или пароль')
            return redirect(url_for('login'))
            
        if not user.is_active:
            flash('Аккаунт заблокирован')
            return redirect(url_for('login'))
            
        login_user(user, remember=remember)
        user.last_login = db.func.now()
        db.session.commit()
        
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Получаем все уроки
    lessons = Lesson.query.order_by(Lesson.order_number).all()
    
    # Для каждого урока проверяем, может ли пользователь его пройти
    for lesson in lessons:
        # Проверяем, есть ли у пользователя доступ к уроку
        lesson.can_access = True  # По умолчанию доступ разрешен
        
        # Если урок требует прохождения предыдущего урока
        if lesson.required_lesson_id:
            # Проверяем, прошел ли пользователь предыдущий урок
            required_lesson = Lesson.query.get(lesson.required_lesson_id)
            if required_lesson:
                # Проверяем, есть ли у пользователя прогресс по предыдущему уроку
                lesson_progress = UserLessonProgress.query.filter_by(
                    user_id=current_user.id,
                    lesson_id=required_lesson.id
                ).first()
                
                # Если нет прогресса или урок не пройден, запрещаем доступ
                if not lesson_progress or not lesson_progress.is_completed:
                    lesson.can_access = False
    
    return render_template('dashboard.html', lessons=lessons)

def create_superadmin():
    """Создание супер-администратора при первом запуске"""
    # Проверяем, существует ли уже супер-админ
    superadmin = User.query.filter_by(is_admin=True).first()
    if not superadmin:
        # Создаем супер-админа
        superadmin = User(
            name='Администратор',  # Добавляем имя
            email='admin@example.com',
            username='admin',
            is_admin=True,
            is_active=True
        )
        superadmin.set_password('admin123')  # В реальном приложении используйте более сложный пароль
        db.session.add(superadmin)
        db.session.commit()
        print('Супер-админ создан')

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)  # Запрет доступа для не-админов
        
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)
        
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        
        # Проверка уникальности имени пользователя
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
            
        # Проверка уникальности email
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
            
        user.username = username
        user.email = email
        
        db.session.commit()
        flash('Данные пользователя успешно обновлены', 'success')
        return redirect(url_for('user_list'))
        
    return render_template('edit_user.html', user=user)

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

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
        
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Нельзя удалить администратора', 'danger')
        return redirect(url_for('user_list'))
        
    db.session.delete(user)
    db.session.commit()
    flash(f'Пользователь {user.username} удален', 'success')
    return redirect(url_for('user_list'))

@app.route('/admin/users')
@login_required
def user_list():
    if not current_user.is_admin:
        abort(403)  # Запрет доступа для не-админов
        
    users = User.query.all()
    return render_template('user_list.html', users=users)

def generate_secure_password(length=12):
    """Генерация безопасного пароля из букв и цифр"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Проверка существования пользователя
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким логином уже существует', 'danger')
            return redirect(url_for('add_user'))
        
        # Создание нового пользователя
        new_user = User(
            name=name,
            username=username,
            email=f"{username}@example.com",  # Генерируем фиктивный email, так как поле обязательное
            is_active=True,
            is_admin=False
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Пользователь {name} успешно создан', 'success')
        return redirect(url_for('user_list'))
    
    # Генерация начального пароля
    initial_password = generate_secure_password()
    return render_template('add_user.html', initial_password=initial_password)

@app.route('/admin/lessons')
@login_required
def lesson_list():
    if not current_user.is_admin:
        abort(403)
    lessons = Lesson.query.order_by(Lesson.order_number).all()
    return render_template('lesson_list.html', lessons=lessons)

@app.route('/admin/lessons/create', methods=['GET', 'POST'])
@login_required
def create_lesson():
    if not current_user.is_admin:
        abort(403)
    
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
def edit_lesson(lesson_id):
    if not current_user.is_admin:
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
    
    lesson = Lesson.query.get_or_404(lesson_id)
    db.session.delete(lesson)
    db.session.commit()
    
    flash('Урок успешно удален', 'success')
    return redirect(url_for('lesson_list'))

@app.route('/admin/lessons/<int:lesson_id>')
@login_required
def view_lesson(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
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
        return redirect(url_for('view_lesson', lesson_id=lesson_id))
    
    # Проверяем, не проходил ли пользователь тест ранее
    previous_result = TestResult.query.filter_by(
        user_id=current_user.id,
        test_id=test.id
    ).first()
    
    if previous_result and previous_result.is_passed:
        flash('Вы уже успешно прошли этот тест')
        return redirect(url_for('view_lesson', lesson_id=lesson_id))
    
    if request.method == 'POST':
        # Создаем новую попытку прохождения теста
        result = TestResult(
            user_id=current_user.id,
            test_id=test.id,
            started_at=datetime.now(),
            answers={}
        )
        
        total_score = 0
        for question in test.questions:
            answer = request.form.get(f'question_{question.id}')
            result.answers[str(question.id)] = answer
            
            if question.question_type == 'single_choice':
                if answer == question.correct_answer:
                    total_score += question.points
            elif question.question_type == 'multiple_choice':
                correct_answers = set(question.correct_answer.split(','))
                user_answers = set(answer.split(',')) if answer else set()
                if correct_answers == user_answers:
                    total_score += question.points
            elif question.question_type == 'text':
                if answer.lower().strip() == question.correct_answer.lower().strip():
                    total_score += question.points
        
        result.score = total_score
        result.is_passed = total_score >= test.required_score
        result.completed_at = datetime.now()
        
        db.session.add(result)
        db.session.commit()
        
        if result.is_passed:
            flash('Поздравляем! Вы успешно прошли тест')
        else:
            flash(f'К сожалению, вы не прошли тест. Набрано баллов: {total_score}')
        
        return redirect(url_for('view_lesson', lesson_id=lesson_id))
    
    return render_template('take_test.html', lesson=lesson, test=test)

@app.route('/lessons/<int:lesson_id>/test/results')
@login_required
def test_results(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)
    test = TheoryTest.query.filter_by(lesson_id=lesson_id).first()
    
    if not test:
        flash('Тест не найден')
        return redirect(url_for('view_lesson', lesson_id=lesson_id))
    
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
        
    if not file.filename.endswith('.txt'):
        flash('Поддерживаются только текстовые файлы (.txt)', 'danger')
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
    tests = []
    order_number = 1
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
            
        # Проверяем, является ли тест скрытым
        is_hidden = line.startswith('#')
        if is_hidden:
            line = line[1:].strip()
            
        # Извлекаем функцию и ожидаемый результат
        try:
            # Удаляем скобки и разделяем на функцию и результат
            line = line.strip('()')
            function_part, expected_output = line.split(',', 1)
            
            # Извлекаем имя функции и аргументы
            function_name = function_part[:function_part.find('(')].strip()
            args = function_part[function_part.find('(')+1:function_part.rfind(')')].strip()
            
            test = {
                'order_number': order_number,
                'function': function_name,
                'input_data': args,
                'expected_output': expected_output.strip(),
                'is_hidden': is_hidden
            }
            
            tests.append(test)
            order_number += 1
            
        except Exception as e:
            print(f"Ошибка при разборе строки: {line}")
            print(f"Ошибка: {str(e)}")
            continue
            
    return tests

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
    
    if request.method == 'POST':
        user_code = request.form.get('code')
        results = []
        
        for test in task.tests:
            try:
                # Создаем временный файл с кодом пользователя
                with open('temp.py', 'w', encoding='utf-8') as f:
                    f.write(user_code)
                
                # Создаем строку для вызова функции с аргументами
                function_call = f"print({test.function}({test.input_data}))"
                
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
                    'function': test.function,
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
                    'function': test.function,
                    'arguments': test.input_data,
                    'expected': test.expected_output,
                    'actual': None,
                    'is_correct': False,
                    'error': str(e),
                    'is_hidden': test.is_hidden
                })
            
            finally:
                # Удаляем временный файл
                if os.path.exists('temp.py'):
                    os.remove('temp.py')
        
        # Проверяем, все ли тесты пройдены
        all_tests_passed = all(r['is_correct'] for r in results)
        
        return render_template('solve_task.html', 
                             task=task, 
                             results=results,
                             all_tests_passed=all_tests_passed,
                             user_code=user_code)
    
    return render_template('solve_task.html', task=task)

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

if __name__ == '__main__':
    with app.app_context():
        # Создаем таблицы, если они не существуют
        db.create_all()
        # Создаем супер-админа, если его нет
        create_superadmin()
    app.run(debug=True) 