"""
VULNERABLE WEB APPLICATION - FOR EDUCATIONAL PURPOSES ONLY
This application contains intentional security vulnerabilities:
- SQL Injection in login authentication
- Cross-Site Scripting (XSS) in error messages and user input display
DO NOT USE IN PRODUCTION
"""

from flask import Flask, request, render_template_string, g, session, redirect, url_for
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'vulnerable-secret-key-12345'  # Weak secret key (vulnerability)
DATABASE = 'vulnerable.db'

# HTML template with XSS vulnerabilities
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Login</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: white;
            padding: 50px 40px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 450px;
            max-width: 90%;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #667eea;
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #333;
            font-weight: 500;
            margin-bottom: 8px;
            font-size: 14px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            margin-top: 10px;
            transition: transform 0.2s;
        }
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        .message {
            padding: 12px 16px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-size: 14px;
        }
        .error {
            background: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }
        .success {
            background: #efe;
            color: #3c3;
            border: 1px solid #cfc;
        }
        .info {
            background: #e7f3ff;
            color: #0066cc;
            border: 1px solid #b3d9ff;
            font-size: 12px;
            margin-top: 20px;
        }
        .links {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .remember-me {
            display: flex;
            align-items: center;
            margin: 15px 0;
        }
        .remember-me input {
            margin-right: 8px;
        }
        .remember-me label {
            margin: 0;
            font-weight: 400;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🏦 SecureBank</h1>
            <p>Online Banking Portal</p>
        </div>
        
        {% if message %}
        <div class="message {{ message_type }}">
            <!-- VULNERABILITY: XSS - Message is rendered without escaping -->
            {{ message|safe }}
        </div>
        {% endif %}
        
        <form method="POST" action="/">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" 
                       value="{{ last_username|safe }}" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <div class="remember-me">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember me on this device</label>
            </div>
            
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        
        <div class="links">
            <a href="#">Forgot Password?</a> • <a href="#">Create Account</a>
        </div>
        
        <div class="message info">
            <strong>💡 Test Credentials:</strong><br>
            Username: <code>admin</code> / Password: <code>password123</code><br>
            <small>Or try SQL injection: <code>' OR '1'='1</code></small>
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .navbar {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            color: white;
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }
        .navbar h1 {
            font-size: 24px;
            font-weight: 700;
        }
        .navbar a {
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            background: rgba(255,255,255,0.2);
            border-radius: 8px;
            transition: background 0.3s;
        }
        .navbar a:hover {
            background: rgba(255,255,255,0.3);
        }
        .container {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        h1 {
            color: white;
            font-size: 72px;
            font-weight: 700;
            text-shadow: 0 10px 30px rgba(0,0,0,0.3);
            animation: fadeIn 1s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .user-info {
            color: white;
            font-size: 18px;
            margin-top: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>🏦 SecureBank</h1>
        <a href="/logout">Logout</a>
    </div>
    
    <div class="container">
        <div>
            <h1>Hello World!</h1>
            <div class="user-info">
                <!-- VULNERABILITY: XSS - Username displayed without escaping -->
                Logged in as: <strong>{{ user.username|safe }}</strong> ({{ user.role|safe }})
            </div>
        </div>
    </div>
</body>
</html>
"""

def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with sample users and transactions"""
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create transactions table
    cursor.execute('''
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            transaction_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Insert sample users
    users = [
        ('admin', 'password123', 'admin@securebank.com', 'admin'),
        ('john', 'john2024', 'john@example.com', 'user'),
        ('sarah', 'sarah123', 'sarah@example.com', 'user'),
        ('mike', 'mike456', 'mike@example.com', 'user'),
    ]
    
    cursor.executemany(
        'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
        users
    )
    
    # Insert sample transactions for admin user (user_id = 1)
    transactions = [
        (1, 'Amazon Purchase', -89.99, '2024-12-08 10:45:00'),
        (1, 'Salary Deposit', 4500.00, '2024-12-01 09:00:00'),
        (1, 'Grocery Store', -125.43, '2024-11-30 18:30:00'),
        (1, 'Electric Bill', -156.00, '2024-11-28 14:15:00'),
        (1, 'Freelance Payment', 800.00, '2024-11-25 11:20:00'),
        (1, 'Netflix Subscription', -15.99, '2024-11-20 08:00:00'),
        (1, 'Restaurant', -67.50, '2024-11-18 19:30:00'),
        (1, 'Gas Station', -45.00, '2024-11-15 07:45:00'),
    ]
    
    cursor.executemany(
        'INSERT INTO transactions (user_id, description, amount, transaction_date) VALUES (?, ?, ?, ?)',
        transactions
    )
    
    db.commit()
    db.close()
    print("✓ Database initialized with sample users and transactions")
    print("✓ Users created: admin, john, sarah, mike")
    print("✓ Sample transactions added for admin user")

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    VULNERABLE LOGIN PAGE
    Contains SQL Injection and XSS vulnerabilities
    """
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    message = None
    message_type = 'error'
    last_username = ''
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        last_username = username
        
        # VULNERABILITY 1: SQL Injection
        # Query is constructed with string concatenation instead of parameterized queries
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        print(f"[SQL INJECTION TEST] Executing query: {query}")
        
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(query)  # Vulnerable to SQL injection!
            user = cursor.fetchone()
            
            if user:
                # Store user in session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['email'] = user['email']
                
                print(f"[LOGIN SUCCESS] User: {username}, Role: {user['role']}")
                return redirect(url_for('dashboard'))
            else:
                # VULNERABILITY 2: XSS in error message
                # Username is reflected in error message WITHOUT ESCAPING
                # This is where XSS payload will execute!
                message = f"❌ Login failed! The username '<strong>{username}</strong>' does not exist or password is incorrect."
                print(f"[LOGIN FAILED] Invalid credentials for: {username}")
                
        except sqlite3.Error as e:
            # VULNERABILITY 3: SQL error messages exposed
            # Also vulnerable to XSS if username contains script tags
            message = f"⚠️ Database error occurred while trying to authenticate user '{username}': {str(e)}"
            print(f"[SQL ERROR] {str(e)}")
    
    return render_template_string(
        LOGIN_TEMPLATE,
        message=message,
        message_type=message_type,
        last_username=last_username
    )

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """
    DASHBOARD PAGE - Simple Hello World
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user data
    user = {
        'username': session.get('username'),
        'role': session.get('role'),
        'email': session.get('email')
    }
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        user=user
    )

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'running', 'vulnerabilities': ['SQL Injection', 'XSS']}, 200

if __name__ == '__main__':
    print("=" * 60)
    print("🚨 SECUREBANK - VULNERABLE WEB APPLICATION 🚨")
    print("=" * 60)
    print("\nInitializing database...")
    init_db()
    print("\nStarting Flask server on http://0.0.0.0:5000")
    print("\n⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("   - SQL Injection in login and search")
    print("   - Cross-Site Scripting (XSS) throughout the application")
    print("   - DO NOT expose this to the internet!")
    print("\n📋 Test Credentials:")
    print("   Username: admin | Password: password123")
    print("   Username: john  | Password: john2024")
    print("\n🎯 Vulnerability Test Payloads:") 
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
