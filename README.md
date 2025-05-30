# Образовательная платформа по программированию

## Описание

Веб-платформа для интерактивного обучения программированию школьников. Поддерживает теоретические уроки, тесты, практические задачи, систему чатов между студентами и учителями, а также административные функции.

---

## Основной функционал

### Пользовательские роли
- **Студент**: прохождение уроков, тестов, решение задач, просмотр комментариев к решениям, чат с учителем.
- **Учитель**: создание и управление студентами, просмотр их прогресса, комментирование решений, чат со студентами.
- **Администратор**: полный контроль над пользователями, уроками, тестами, задачами и настройками.

### Уроки и обучение
- Многоуровневая система уроков с последовательным доступом.
- Каждый урок содержит теорию, тест и практические задачи.
- Прогресс по уроку фиксируется по блокам: теория, тест, практика.

### Тесты
- Теоретические тесты с поддержкой разных типов вопросов (один/несколько вариантов, текст).
- Автоматическая проверка и хранение результатов.

### Практические задачи
- Решение задач с автоматической проверкой кода по тестам.
- Система комментариев к решениям от учителя/админа.

### Чат
- Студент может общаться только со своим учителем.
- Учитель видит список своих студентов и может вести чат с каждым.
- Реализация на WebSocket (Flask-SocketIO) — сообщения обновляются в реальном времени.
- Уведомления о новых сообщениях и непрочитанных комментариях к решениям.

### Администрирование
- Управление пользователями (создание, редактирование, удаление, блокировка).
- Управление уроками, тестами, задачами.
- Просмотр прогресса и достижений студентов.

---

## Структура проекта

- `app.py` — основной файл приложения Flask
- `models.py` — модели SQLAlchemy (если вынесены)
- `templates/` — HTML-шаблоны (Jinja2)
- `static/css/` — стили CSS
- `static/js/` — JS-скрипты
- `migrations/` — миграции базы данных
- `requirements.txt` — зависимости Python

---

## Установка и запуск

1. Клонируйте репозиторий и перейдите в папку проекта:
   ```bash
   git clone ...
   cd project_site
   ```
2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
3. Настройте переменные окружения (например, SECRET_KEY, DATABASE_URL).
4. Инициализируйте базу данных:
   ```bash
   flask db upgrade
   ```
5. Запустите приложение:
   ```bash
   python app.py
   ```
6. Откройте в браузере: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)

---

## Технические детали
- Flask, Flask-SQLAlchemy, Flask-Login, Flask-Migrate, Flask-SocketIO
- Bootstrap 5 для UI
- Поддержка тем оформления
- Безопасность: проверка кода, ограничения на доступ, защита от опасных операций

---

## Контакты и поддержка
По вопросам и предложениям обращайтесь к разработчику. 