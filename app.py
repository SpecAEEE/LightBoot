from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import secrets
import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

app = Flask(__name__)
CORS(app)

# Use Environment Variables for security on Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-fallback-key-change-this')
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    # Connects to Render's PostgreSQL database
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Licenses table
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            license_key TEXT UNIQUE NOT NULL,
            activation_key TEXT UNIQUE NOT NULL,
            valid_until TIMESTAMP NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP,
            hwid TEXT
        )
    """)
    
    conn.commit()
    c.close()
    conn.close()
    print("[DB] PostgreSQL Database initialized")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"success": False, "message": "Missing token"}), 401
        
        try:
            token = token.split(" ")[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_id = payload['user_id']
            request.username = payload['username']
        except:
            return jsonify({"success": False, "message": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not username or not email or not password or len(password) < 6:
        return jsonify({"success": False, "message": "Invalid input"}), 400
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id", 
                  (username, email, password_hash))
        user_id = c.fetchone()[0]
        conn.commit()
        c.close()
        conn.close()

        token = jwt.encode({
            'user_id': user_id,
            'username': username,
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({"success": True, "token": token, "user_id": user_id}), 201
    except psycopg2.IntegrityError:
        return jsonify({"success": False, "message": "Username or email exists"}), 409
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username, password = data.get('username', '').strip(), data.get('password', '')
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT id, username FROM users WHERE username = %s AND password_hash = %s", (username, password_hash))
        user = c.fetchone()
        c.close()
        conn.close()

        if not user:
            return jsonify({"success": False, "message": "Invalid credentials"}), 401
        
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({"success": True, "token": token, "user_id": user[0]}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/validate-license', methods=['POST'])
@token_required
def validate_license():
    data = request.json
    license_key, hwid = data.get('license_key', '').strip(), data.get('hwid', '')
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, valid_until, active, hwid FROM licenses WHERE license_key = %s AND user_id = %s", 
                  (license_key, request.user_id))
        lic = c.fetchone()
        
        if not lic:
            return jsonify({"success": False, "message": "Not found"}), 404
        
        lic_id, valid_until, active, stored_hwid = lic
        
        if not active or valid_until < datetime.now():
            return jsonify({"success": False, "message": "Inactive or expired"}), 403
        
        if stored_hwid and hwid and stored_hwid != hwid:
            return jsonify({"success": False, "message": "HWID mismatch"}), 403
        
        c.execute("UPDATE licenses SET last_used = CURRENT_TIMESTAMP WHERE id = %s", (lic_id,))
        conn.commit()
        c.close()
        conn.close()
        
        return jsonify({"success": True, "message": "License valid"}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# Keep-Alive and Health Check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    init_db()
    app.run()
