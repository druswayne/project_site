from datetime import datetime

class PracticeTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lesson_id = db.Column(db.Integer, db.ForeignKey('lesson.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    is_required = db.Column(db.Boolean, default=True)
    order_number = db.Column(db.Integer, nullable=False)
    tests = db.relationship('TaskTest', backref='task', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<PracticeTask {self.title}>'

class TaskTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('practice_task.id'), nullable=False)
    input_data = db.Column(db.Text, nullable=False)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_correct = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('solutions', lazy=True))
    task = db.relationship('PracticeTask', backref=db.backref('solutions', lazy=True))

    def __repr__(self):
        return f'<Solution {self.id}>' 