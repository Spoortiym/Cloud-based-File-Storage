from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import mysql.connector
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change this in production

# Folder to save uploaded files
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to get user-specific upload folder
def get_user_upload_folder(username):
    # Sanitize username by replacing spaces with underscores
    sanitized_username = username.replace(' ', '_')
    user_folder = os.path.join(UPLOAD_FOLDER, sanitized_username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder

# MySQL connection
db = mysql.connector.connect(
    host="localhost",
    user="root",           # your MySQL username
    password="#Spoorti8088",           # your MySQL password (blank if using XAMPP default)
    database="cloud_storage"
)
cursor = db.cursor()

# Dummy users database (replace with MySQL later)
users = {}

# Home redirects to login
@app.route('/')
def home():
    return redirect('/login')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        if user:
            session['user'] = username
            return redirect('/dashboard')
        else:
            return "Invalid credentials!"

    return render_template('login.html')

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    print("🔁 /register route triggered")
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match!")
        
        try:
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                return render_template('register.html', error="Username already exists!")
            
            # Insert new user
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, password))
            db.commit()
            return redirect('/login')
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return render_template('register.html', error="Registration failed. Please try again.")
    
    return render_template('register.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    
    username = session['user']
    user_folder = get_user_upload_folder(username)
    
    # Check if the folder exists, if not create it
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    files = os.listdir(user_folder)
    now = datetime.now()
    return render_template('dashboard.html', files=files, user=username, now=now)

# File Upload
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect('/login')
    
    username = session['user']
    user_folder = get_user_upload_folder(username)
    
    # Check if the folder exists, if not create it
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    file = request.files['file']
    if file:
        file.save(os.path.join(user_folder, file.filename))
    return redirect('/dashboard')

# File Download
@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect('/login')
    
    username = session['user']
    user_folder = get_user_upload_folder(username)
    
    # Check if the folder exists, if not create it
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    return send_from_directory(user_folder, filename, as_attachment=True)

# File Delete
@app.route('/delete/<filename>')
def delete(filename):
    if 'user' not in session:
        return redirect('/login')
    
    username = session['user']
    user_folder = get_user_upload_folder(username)
    
    # Check if the folder exists, if not create it
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    file_path = os.path.join(user_folder, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect('/dashboard')

# Profile Page
@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')
    
    username = session['user']
    
    # Get user information from database
    cursor.execute("SELECT username, email FROM users WHERE username = %s", (username,))
    user_info = cursor.fetchone()
    
    if user_info:
        username, email = user_info
    else:
        username = session['user']
        email = "Not available"
    
    return render_template('profile.html', username=username, email=email)

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

if __name__ == '__main__':
    # Create uploads folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

