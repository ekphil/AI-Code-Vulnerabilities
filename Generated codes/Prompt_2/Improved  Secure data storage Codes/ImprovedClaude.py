from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
import os
from datetime import datetime, timedelta
from functools import wraps
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Configure logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)

# Security headers
Talisman(app, 
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'"
    }
)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

# Configuration
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY=os.urandom(32),  # 32 bytes for better security
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Session timeout
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    account_locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        # Password complexity validation
        if not self.is_password_complex(password):
            raise ValueError("Password does not meet complexity requirements")
        self.password_hash = bcrypt.generate_password_hash(password, rounds=12).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    @staticmethod
    def is_password_complex(password):
        """
        Password must:
        - Be at least 12 characters long
        - Contain at least one uppercase letter
        - Contain at least one lowercase letter
        - Contain at least one number
        - Contain at least one special character
        """
        if len(password) < 12:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")  # Limit registration attempts
def register():
    try:
        data = request.get_json()
        
        # Input validation
        if not data or not all(k in data for k in ('username', 'password', 'email')):
            return jsonify({'error': 'Missing required fields'}), 400

        # Sanitize and validate username
        username = str(data['username']).strip()
        if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username):
            return jsonify({'error': 'Invalid username format'}), 400

        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        # Create new user
        new_user = User(
            username=username,
            email=data['email'].lower()
        )
        
        try:
            new_user.set_password(data['password'])
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        db.session.add(new_user)
        db.session.commit()

        logging.info(f"New user registered: {username}")
        return jsonify({'message': 'User registered successfully'}), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        db.session.rollback()
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'An error occurred during registration'}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Limit login attempts
def login():
    try:
        data = request.get_json()
        
        if not data or not all(k in data for k in ('username', 'password')):
            return jsonify({'error': 'Missing required fields'}), 400

        user = User.query.filter_by(username=data['username']).first()
        
        # Check if account is locked
        if user and user.account_locked_until and user.account_locked_until > datetime.utcnow():
            return jsonify({'error': 'Account is temporarily locked'}), 403

        if user and user.check_password(data['password']):
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.last_login_attempt = datetime.utcnow()
            db.session.commit()
            
            # Set session
            session.permanent = True
            session['user_id'] = user.id
            session.modified = True

            logging.info(f"Successful login: {user.username}")
            return jsonify({'message': 'Login successful'}), 200
        else:
            if user:
                # Increment failed login attempts
                user.failed_login_attempts += 1
                user.last_login_attempt = datetime.utcnow()
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                    logging.warning(f"Account locked due to failed attempts: {user.username}")
                
                db.session.commit()
            
            logging.warning(f"Failed login attempt for username: {data.get('username')}")
            return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/logout', methods=['POST'])
@require_login
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# Error handlers
@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    logging.error(f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False, ssl_context='adhoc')  # Enable HTTPS in development