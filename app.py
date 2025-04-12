from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from datetime import datetime
import secrets
import string

load_dotenv()

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
    initial_code = db.Column(db.Text)
    test_cases = db.Column(db.JSON)  # Список тестовых случаев
    solution = db.Column(db.Text)  # Пример решения

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
    return render_template('dashboard.html')

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

@app.route('/admin/lessons/<int:lesson_id>/tasks/add', methods=['GET', 'POST'])
@login_required
def add_practice_task(lesson_id):
    if not current_user.is_admin:
        abort(403)
    
    lesson = Lesson.query.get_or_404(lesson_id)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        initial_code = request.form.get('initial_code')
        test_cases = request.form.get('test_cases')
        solution = request.form.get('solution')
        
        task = PracticeTask(
            lesson_id=lesson.id,
            title=title,
            description=description,
            initial_code=initial_code,
            test_cases=test_cases,
            solution=solution
        )
        
        db.session.add(task)
        db.session.commit()
        flash('Практическая задача успешно добавлена', 'success')
        return redirect(url_for('view_lesson', lesson_id=lesson.id))
    
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

if __name__ == '__main__':
    with app.app_context():
        # Создаем таблицы, если они не существуют
        db.create_all()
        # Создаем супер-админа, если его нет
        create_superadmin()
    app.run(debug=True) 