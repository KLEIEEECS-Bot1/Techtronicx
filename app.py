import sqlite3
import threading
import time
import requests
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# --- CONFIGURATION ---
app = Flask(__name__)
CORS(app) # Allow requests from the frontend
app.config['SECRET_KEY'] = 'your-super-secret-key-for-jwt' # Change this in production
DATABASE_NAME = 'crypto_alerts.db'
PRICE_CHECK_INTERVAL_SECONDS = 30 # Check prices every 30 seconds

# --- DATABASE SETUP ---
def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Creates the necessary database tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Create alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            crypto_id TEXT NOT NULL,
            condition TEXT NOT NULL CHECK(condition IN ('above', 'below')),
            threshold REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'triggered')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            triggered_at TIMESTAMP,
            triggered_price REAL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

# --- BACKGROUND PRICE CHECKER ---
def price_checker_task():
    """
    A background task that runs periodically to check crypto prices
    and trigger alerts.
    """
    print("Price checker task started.")
    while True:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # 1. Get all active alerts
            active_alerts = cursor.execute("SELECT * FROM alerts WHERE status = 'active'").fetchall()
            
            if not active_alerts:
                conn.close()
                time.sleep(PRICE_CHECK_INTERVAL_SECONDS)
                continue

            # 2. Get unique crypto IDs to fetch prices efficiently
            crypto_ids = list(set([alert['crypto_id'] for alert in active_alerts]))
            ids_string = ','.join(crypto_ids)
            
            # 3. Fetch current prices from CoinGecko API
            price_url = f'https://api.coingecko.com/api/v3/simple/price?ids={ids_string}&vs_currencies=usd'
            response = requests.get(price_url)
            prices = response.json()

            # 4. Check each alert against the current price
            for alert in active_alerts:
                crypto_id = alert['crypto_id']
                if crypto_id in prices and 'usd' in prices[crypto_id]:
                    current_price = prices[crypto_id]['usd']
                    threshold = alert['threshold']
                    condition = alert['condition']
                    
                    # Check if the condition is met
                    if (condition == 'above' and current_price > threshold) or \
                       (condition == 'below' and current_price < threshold):
                        
                        # Update the alert to 'triggered'
                        cursor.execute('''
                            UPDATE alerts 
                            SET status = 'triggered', triggered_at = ?, triggered_price = ?
                            WHERE id = ?
                        ''', (datetime.utcnow(), current_price, alert['id']))
                        print(f"Triggered alert ID {alert['id']} for {crypto_id} at ${current_price}")

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"Error in price checker task: {e}")
        
        time.sleep(PRICE_CHECK_INTERVAL_SECONDS)


# --- AUTHENTICATION HELPER ---
from functools import wraps
def token_required(f):
    """Decorator to protect routes that require a valid JWT."""
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Expected format: "Bearer <token>"
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid!'}), 401
        
        return f(current_user_id, *args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


# --- API ENDPOINTS ---
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    user = cursor.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user:
        conn.close()
        return jsonify({'error': 'Email address already in use'}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hashed_password))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Account created successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid email or password'}), 401
        
    # Generate JWT
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + timedelta(hours=24) # Token expires in 24 hours
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({'message': 'Login successful', 'token': token})


@app.route('/api/alerts', methods=['GET'])
@token_required
def get_alerts(current_user_id):
    conn = get_db_connection()
    
    active_alerts_rows = conn.execute(
        "SELECT * FROM alerts WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC", 
        (current_user_id,)
    ).fetchall()
    
    triggered_alerts_rows = conn.execute(
        "SELECT * FROM alerts WHERE user_id = ? AND status = 'triggered' ORDER BY triggered_at DESC",
        (current_user_id,)
    ).fetchall()
    
    conn.close()
    
    # Convert row objects to dictionaries for JSON serialization
    active_alerts = [dict(row) for row in active_alerts_rows]
    triggered_alerts = [dict(row) for row in triggered_alerts_rows]
    
    return jsonify({'active': active_alerts, 'triggered': triggered_alerts})


@app.route('/api/alerts', methods=['POST'])
@token_required
def create_alert(current_user_id):
    data = request.get_json()
    crypto_id = data.get('id')
    threshold = data.get('threshold')
    condition = data.get('condition')

    if not all([crypto_id, threshold, condition]):
        return jsonify({'error': 'Missing data for alert'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO alerts (user_id, crypto_id, threshold, condition) VALUES (?, ?, ?, ?)",
        (current_user_id, crypto_id, threshold, condition)
    )
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()

    return jsonify({'message': 'Alert created successfully', 'alert_id': alert_id}), 201


@app.route('/api/alerts/delete', methods=['POST'])
@token_required
def delete_alert(current_user_id):
    data = request.get_json()
    alert_id = data.get('id')

    if not alert_id:
        return jsonify({'error': 'Alert ID is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Ensure the user owns this alert before deleting
    result = cursor.execute(
        "DELETE FROM alerts WHERE id = ? AND user_id = ?",
        (alert_id, current_user_id)
    )
    conn.commit()
    conn.close()

    if result.rowcount == 0:
        return jsonify({'error': 'Alert not found or you do not have permission to delete it'}), 404

    return jsonify({'message': 'Alert deleted successfully'})


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    initialize_database()
    # Start the background thread for checking prices
    checker_thread = threading.Thread(target=price_checker_task, daemon=True)
    checker_thread.start()
    # Run the Flask web server
    app.run(debug=True, port=5001)