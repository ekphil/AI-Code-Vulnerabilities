from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Flask_Bcrypt
from sqlalchemy.exc import IntegrityError
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)
bcrypt = Flask_Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate input
    if not data or not all(k in data for k in ('username', 'password', 'email')):
        return jsonify({'error': 'Missing required fields'}), 400

    # Additional validation
    if len(data['password']) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        # Create new user
        new_user = User(
            username=data['username'], 
            email=data['email']
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not all(k in data for k in ('username', 'password')):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=False)