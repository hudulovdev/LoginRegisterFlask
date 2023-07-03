from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key

# Mock user data
users = [
    {'username': 'user1', 'password': generate_password_hash('password1')},
    {'username': 'user2', 'password': generate_password_hash('password2')}
]

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        users.append({'username': username, 'password': hashed_password})
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users:
            if user['username'] == username and check_password_hash(user['password'], password):
                session['username'] = username
                return redirect('/')
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
