from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_marshmallow import Marshmallow
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import re

# Initialize the app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Secure configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "users.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
app.config['SECRET_KEY'] = os.urandom(24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
ma = Marshmallow(app)
limiter = Limiter(get_remote_address, app=app)

# Password policy
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# User schema for serialization
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Helper functions
def validate_password(password):
    """Validate password against policy."""
    return PASSWORD_REGEX.match(password)

# Endpoint to register a user
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if len(username) < 3 or len(username) > 20 or not username.isalnum():
        return jsonify({"message": "Username must be 3-20 characters and alphanumeric"}), 400

    if not validate_password(password):
        return jsonify({"message": "Password must be at least 8 characters long, include one letter, one number, and one special character"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Invalid username or password"}), 401

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Endpoint to log in a user
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        # In a real-world app, generate a secure token (e.g., JWT) here
        return jsonify({"message": "Login successful"}), 200

    return jsonify({"message": "Invalid username or password"}), 401

# Restricted endpoint (for admin usage only, secured with a simple hardcoded token)
@app.route('/users', methods=['GET'])
@limiter.limit("5 per minute")
def get_users():
    token = request.headers.get('Authorization')
    if token != 'Bearer admin-secret-token':  # Replace with a secure mechanism in production
        return jsonify({"message": "Unauthorized"}), 403

    users = User.query.all()
    return jsonify(users_schema.dump(users))

# Initialize the database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    # Run the app securely
    app.run(debug=False, ssl_context='adhoc')  # Use a proper certificate in production
