from flask import Flask, render_template, request, jsonify
import sys
from io import StringIO
import contextlib

app = Flask(__name__)

# Пример задачи и тестов
TASK = {
    'title': 'Сумма двух чисел',
    'description': '''Напишите функцию sum_numbers(a, b), которая принимает два числа и возвращает их сумму.

Примеры работы функции:
sum_numbers(2, 3) → 5
sum_numbers(-1, 1) → 0
sum_numbers(0, 0) → 0
sum_numbers(10, -5) → 5''',
    'tests': [
        {'input': 'sum_numbers(2, 3)', 'expected': 5},
        {'input': 'sum_numbers(-1, 1)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0},
        {'input': 'sum_numbers(2, 3)', 'expected': 5},
        {'input': 'sum_numbers(-1, 1)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0},
        {'input': 'sum_numbers(0, 0)', 'expected': 0}
    ]
}

def run_code(code):
    # Создаем StringIO для перехвата вывода
    output = StringIO()
    error_output = StringIO()
    
    try:
        # Выполняем код в изолированном пространстве имен
        namespace = {}
        with contextlib.redirect_stdout(output):
            exec(code, namespace)
        
        # Проверяем наличие функции sum_numbers
        if 'sum_numbers' not in namespace:
            return {'success': False, 'error': 'Функция sum_numbers не найдена'}
        
        # Запускаем тесты
        results = []
        for test in TASK['tests']:
            try:
                result = eval(test['input'], namespace)
                passed = result == test['expected']
                results.append({
                    'test': test['input'],
                    'passed': passed,
                    'result': result,
                    'expected': test['expected']
                })
            except Exception as e:
                results.append({
                    'test': test['input'],
                    'passed': False,
                    'error': str(e)
                })
        
        return {
            'success': True,
            'results': results,
            'output': output.getvalue()
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

@app.route('/')
def index():
    return render_template('index.html', task=TASK)

@app.route('/run', methods=['POST'])
def run():
    code = request.json.get('code', '')
    result = run_code(code)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True) 