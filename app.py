from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import os
import sqlite3
import shutil
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key

# Database configuration
DATABASE = os.path.abspath('cloud_storage.db')
print(f"Database path: {DATABASE}")

def get_db():
    global DATABASE
    
    # Create the database file if it doesn't exist
    if not os.path.exists(DATABASE):
        print(f"Database file {DATABASE} does not exist. Creating it...")
        try:
            with open(DATABASE, 'w') as f:
                pass
            print(f"Created empty database file: {DATABASE}")
        except Exception as e:
            print(f"Error creating database file: {str(e)}")
            # Try with a different path
            alt_database = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage.db')
            print(f"Trying alternative database path: {alt_database}")
            with open(alt_database, 'w') as f:
                pass
            print(f"Created empty database file at alternative path: {alt_database}")
            DATABASE = alt_database
    
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        
        # Check if the users table exists
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("Users table not found. Creating tables...")
            # Read and execute the schema.sql file
            schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
            print(f"Schema path: {schema_path}")
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
                print(f"Schema SQL: {schema_sql}")
                cursor.executescript(schema_sql)
            db.commit()
            print("Database tables created successfully.")
        
        return db
    except Exception as e:
        print(f"Error in get_db: {str(e)}")
        raise e

def init_db():
    print("Initializing database...")
    try:
        # Just call get_db to ensure the database and tables are created
        db = get_db()
        
        # Verify that the users table exists
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("Users table still not found after get_db. Trying direct creation...")
            # Try to create the table directly
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            db.commit()
            print("Users table created directly.")
        
        db.close()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        # Don't raise the exception, just log it
        # This allows the application to start even if there's a database error
        # The database will be created when needed

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    try:
        os.makedirs(UPLOAD_FOLDER, mode=0o755, exist_ok=True)
        print(f"Created uploads directory: {UPLOAD_FOLDER}")
    except Exception as e:
        print(f"Error creating uploads directory: {str(e)}")
        # Try with absolute path
        try:
            abs_path = os.path.abspath(UPLOAD_FOLDER)
            os.makedirs(abs_path, mode=0o755, exist_ok=True)
            print(f"Created uploads directory with absolute path: {abs_path}")
        except Exception as e2:
            print(f"Error creating uploads directory with absolute path: {str(e2)}")

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_user_upload_folder(username):
    # Sanitize the username to create a safe folder name
    safe_username = secure_filename(username)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], safe_username)
    
    print(f"Original username: {username}")
    print(f"Safe username: {safe_username}")
    print(f"User folder path: {user_folder}")
    
    # Create the folder if it doesn't exist
    if not os.path.exists(user_folder):
        try:
            os.makedirs(user_folder, mode=0o755, exist_ok=True)
            print(f"Created user folder: {user_folder}")
        except Exception as e:
            print(f"Error creating user folder: {str(e)}")
            # Try an alternative approach if the first one fails
            try:
                # Try with absolute path
                abs_path = os.path.abspath(user_folder)
                os.makedirs(abs_path, mode=0o755, exist_ok=True)
                print(f"Created user folder with absolute path: {abs_path}")
            except Exception as e2:
                print(f"Error creating user folder with absolute path: {str(e2)}")
                # If both attempts fail, we'll handle this in the calling function
    
    return user_folder

# Context processor to make current time available to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.datetime.now()}

@app.route('/')
def index():
    # Clear any existing session
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            
            # Validate input
            if not username or not password or not email:
                flash('All fields are required!')
                return redirect(url_for('register'))
            
            # Ensure database is initialized
            try:
                db = get_db()
            except Exception as e:
                print(f"Database error: {str(e)}")
                # Try to initialize the database
                try:
                    init_db()
                    db = get_db()
                except Exception as e2:
                    print(f"Failed to initialize database: {str(e2)}")
                    flash('Database error. Please try again later.')
                    return redirect(url_for('register'))
            
            cursor = db.cursor()
            
            # Check if username already exists
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash('Username already exists!')
                return redirect(url_for('register'))
            
            # Create new user
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                          (username, hashed_password, email))
            db.commit()
            
            # Create user's upload folder
            try:
                user_folder = get_user_upload_folder(username)
                print(f"Created user folder: {user_folder}")
            except Exception as e:
                print(f"Error creating user folder: {str(e)}")
                # Continue with registration even if folder creation fails
                # We'll create it when needed
            
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Registration error: {str(e)}")
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'username' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login to access the dashboard.')
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = get_user_upload_folder(username)
    
    print(f"Current username: {username}")
    print(f"User folder path: {user_folder}")
    print(f"Folder exists: {os.path.exists(user_folder)}")
    
    # Ensure the user folder exists
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    files = []
    try:
        print(f"Listing files in: {user_folder}")
        for filename in os.listdir(user_folder):
            file_path = os.path.join(user_folder, filename)
            print(f"Found file: {filename}")
            if os.path.isfile(file_path):  # Only include files, not directories
                file_stats = os.stat(file_path)
                files.append({
                    'name': filename,
                    'size': file_stats.st_size,
                    'modified': datetime.datetime.fromtimestamp(file_stats.st_mtime)
                })
    except Exception as e:
        print(f"Error reading files: {str(e)}")
        flash(f'Error reading files: {str(e)}')
    
    print(f"Total files found: {len(files)}")
    return render_template('dashboard.html', files=files, username=username)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        flash('Please login to upload files.')
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected!')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected!')
        return redirect(url_for('dashboard'))
    
    if file:
        try:
            username = session['username']
            user_folder = get_user_upload_folder(username)
            
            # Ensure the user folder exists
            if not os.path.exists(user_folder):
                os.makedirs(user_folder)
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(user_folder, filename)
            
            # Save the file
            file.save(file_path)
            
            # Verify the file was saved
            if os.path.exists(file_path):
                flash(f'File "{filename}" uploaded successfully!')
            else:
                flash('Error saving file. Please try again.')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = get_user_upload_folder(username)
    return send_file(os.path.join(user_folder, secure_filename(filename)), as_attachment=True)

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = get_user_upload_folder(username)
    file_path = os.path.join(user_folder, secure_filename(filename))
    
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('File deleted successfully!')
    else:
        flash('File not found!')
    
    return redirect(url_for('dashboard'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    print(f"Current session username: {username}")  # Debug print
    
    db = get_db()
    cursor = db.cursor()
    
    # Get user from database
    cursor.execute('SELECT username, email FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    print(f"Database query result: {user}")  # Debug print
    
    if user is None:
        print(f"User {username} not found in database")  # Debug print
        session.clear()
        flash('User account not found. Please login again.')
        return redirect(url_for('login'))
    
    return render_template('profile.html', username=user['username'], email=user['email'])

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_username = session['username']
    print(f"Updating profile for user: {current_username}")  # Debug print
    
    new_username = request.form.get('new_username')
    new_email = request.form.get('new_email')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    print(f"Form data - new_username: {new_username}, new_email: {new_email}")  # Debug print
    
    # Validate required fields
    if not current_password:
        flash('Current password is required to update profile')
        return redirect(url_for('profile'))
    
    if not new_username and not new_email and not new_password:
        flash('No changes were made to the profile')
        return redirect(url_for('profile'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Get current user
        cursor.execute('SELECT * FROM users WHERE username = ?', (current_username,))
        user = cursor.fetchone()
        print(f"Database query result: {user}")  # Debug print
        
        if user is None:
            print(f"User {current_username} not found in database")  # Debug print
            session.clear()
            flash('User account not found. Please login again.')
            return redirect(url_for('login'))
        
        # Verify current password
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect!')
            return redirect(url_for('profile'))
        
        # Check if new username already exists (if username is being changed)
        if new_username and new_username != current_username:
            cursor.execute('SELECT * FROM users WHERE username = ?', (new_username,))
            if cursor.fetchone():
                flash('Username already exists!')
                return redirect(url_for('profile'))
            
            # Update username in database
            cursor.execute('UPDATE users SET username = ? WHERE username = ?', 
                          (new_username, current_username))
            session['username'] = new_username
            
            # Handle folder renaming
            old_folder = get_user_upload_folder(current_username)
            new_folder = get_user_upload_folder(new_username)
            
            if os.path.exists(old_folder):
                # If new folder exists, remove it first
                if os.path.exists(new_folder):
                    shutil.rmtree(new_folder)
                # Move the old folder to the new location
                shutil.move(old_folder, new_folder)
                flash(f'Username updated from {current_username} to {new_username}')
        
        if new_email:
            cursor.execute('UPDATE users SET email = ? WHERE username = ?', 
                          (new_email, session['username']))
            flash('Email updated successfully')
        
        if new_password:
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', 
                          (hashed_password, session['username']))
            flash('Password updated successfully')
        
        db.commit()
        print("Profile update successful")  # Debug print
        
    except Exception as e:
        print(f"Error updating profile: {str(e)}")  # Debug print
        db.rollback()
        flash(f'Error updating profile: {str(e)}')
        return redirect(url_for('profile'))
    
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    password = request.form.get('password')
    
    db = get_db()
    cursor = db.cursor()
    
    # Verify password
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not check_password_hash(user['password'], password):
        flash('Password is incorrect!')
        return redirect(url_for('profile'))
    
    # Delete user files
    user_folder = get_user_upload_folder(username)
    if os.path.exists(user_folder):
        try:
            # Try to delete each file individually first
            for filename in os.listdir(user_folder):
                file_path = os.path.join(user_folder, filename)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(f"Error deleting file {filename}: {str(e)}")
            
            # Try to remove the directory
            try:
                os.rmdir(user_folder)
            except Exception as e:
                print(f"Error removing directory: {str(e)}")
                # Continue with account deletion even if directory removal fails
        except Exception as e:
            print(f"Error during file deletion: {str(e)}")
            # Continue with account deletion even if file deletion fails
    
    # Delete user from database
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    db.commit()
    
    # Clear session
    session.pop('username', None)
    flash('Account deleted successfully!')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Clear the entire session
    session.clear()
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("Starting application...")
    
    # Make sure the database directory exists and is writable
    db_dir = os.path.dirname(DATABASE)
    if not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, mode=0o755, exist_ok=True)
            print(f"Created database directory: {db_dir}")
        except Exception as e:
            print(f"Error creating database directory: {str(e)}")
    
    # Initialize the database
    try:
        init_db()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        # Continue anyway, the database will be created when needed
    
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=True)
