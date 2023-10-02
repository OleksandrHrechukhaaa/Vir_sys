from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt

app = Flask(__name__)


#Заголовок бещпеки
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Шлях до бази даних SQLite
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
db = SQLAlchemy(app)

# Модель користувача для бази даних
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Секретний ключ для створення кукі
app.secret_key = 'your_secret_key'

# Функція для перевірки паролю
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return True
    return False

# Ініціалізація бази даних в контексті додатку
with app.app_context():
    db.create_all()


# Шлях до початкової сторінки
@app.route('/')
def index():
    return render_template('enter.html')
   

@app.route('/login', methods=['POST'])
def login():
    username = request.form['loginUsername']
    password = request.form['loginPassword']
    error_message = None

    if verify_password(username, password):
        # Якщо пароль вірний, створюємо куку для користувача
        response = make_response(redirect('/dashboard'))
        response.set_cookie('username', username)
        return response
    else:
        error_message = "Неправильний логін або пароль"
        return render_template('enter.html', error=error_message)
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Користувач з таким іменем вже існує"
        else:
            # Хешуємо пароль перед збереженням у базу даних
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password=hashed_password.decode('utf-8'))
            db.session.add(new_user)
            db.session.commit()

            return redirect('/dashboard')
    else:
        return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    # Перевіряємо, чи існує кука з іменем користувача
    username = request.cookies.get('username')
    if username:
        return render_template('dashboard.html')
    else:
        return redirect('/')


@app.route('/change_pass_button')
def indoors_page():
    # Перевіряємо, чи існує кука з іменем користувача
    username = request.cookies.get('username')
    if username:
        return render_template('indors_page.html', username=username)
    else:
        return redirect('/')


@app.route('/logout')
def logout():
    # Отримати відповідь, щоб видалити куку
    response = make_response(redirect("/"))
    
    # Видалити куку, яка містить ім'я користувача
    response.delete_cookie('username')
    
    return response

# Маршрут для зміни паролю
@app.route('/changepassword', methods=['POST'])
def change_password():
    # Отримати дані з форми
    current_password = request.form['currentPassword']
    new_password = request.form['newPassword']
    confirm_password = request.form['confirmPassword']
    error_message = None  # Змінна для збереження повідомлення про помилку
    success_message = None  # Змінна для збереження повідомлення про успіх
    # Отримати ім'я користувача з кукі
    username = request.cookies.get('username')
    
    # Перевірити чи введений новий пароль і його підтвердження співпадають
    if new_password != confirm_password:
        error_message = "Паролі не співпадають."
        return render_template('indors_page.html', error=error_message)
    
    # Перевірити чи старий та новий паролі різняться
    if current_password == new_password:
        error_message = "Новий пароль не може бути таким самим, як старий пароль"
        return render_template('indors_page.html', error=error_message)

    # Перевіряє чи поточний пароль користувача вірний якщо так то змінює пароль, якщо ні то повертає помилку
    if verify_password(username, current_password):
        # Генеруємо нову сіль
        new_salt = bcrypt.gensalt()
        
        # Хешуємо новий пароль з новою сіллю
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), new_salt)
        
        # Оновлюємо поле паролю та солі користувача в базі даних
        user = User.query.filter_by(username=username).first()
        user.password = new_password_hash.decode('utf-8')  # Зберігаємо новий хеш паролю
        user.salt = new_salt.decode('utf-8')  # Зберігаємо нову сіль
        
        db.session.commit()
        success_message = "Пароль успішно змінено"
        return render_template('indors_page.html', success_message=success_message)
    else:
        error_message = "Неправильний поточний пароль"
        return render_template('indors_page.html', error=error_message)

@app.route('/back_to_main')
def back_to_main():
    return render_template('/dashboard.html')

@app.route('/backend-endpoint', methods=['POST'])
def backend_endpoint():
    data = request.get_json()  # Отримати дані в форматі JSON з запиту
    username = data['username']
    password = data['password']

    # Опрацьовуйте отримані дані, наприклад, збережіть їх у базі даних або виконайте іншу логіку

    # Поверніть відповідь на фронтенд
    response = {'message': 'Дані успішно отримані на бекенді'}
    return jsonify(response), 200


if __name__ == '__main__':
    app.run(debug=True)
    
