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
    is_correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    task = db.relationship('PracticeTask', backref=db.backref('solutions', lazy=True))
    user = db.relationship('User', backref=db.backref('solutions', lazy=True))

    def __repr__(self):
        return f'<Solution {self.id}>'

class SolutionComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    solution_id = db.Column(db.Integer, db.ForeignKey('solution.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    
    solution = db.relationship('Solution', backref=db.backref('comments', lazy=True))
    admin = db.relationship('User', backref=db.backref('solution_comments', lazy=True)) 