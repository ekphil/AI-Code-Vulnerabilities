from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from argon2 import PasswordHasher
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from marshmallow import Schema, fields, validate
from flask_limiter import Limiter
from flask_sslify import SSLify
from flask_logconfig import LogConfig

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["JWT_SECRET_KEY"] = "super-secret-key"
app.config["ARGON2_HASHING"] = True

db = SQLAlchemy(app)
jwt = JWTManager(app)
limiter = Limiter(app, key_func=get_remote_address)
sslify = SSLify(app)
log_config = LogConfig(app)

ph = PasswordHasher()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = ph.hash(password)


class UserSchema(Schema):
    username = fields.String(required=True, validate=validate.Length(min=3, max=64))
    password = fields.String(required=True, validate=validate.Length(min=8, max=128))


@app.route("/register", methods=["POST"])
@limiter.limit("5/minute")
def register():
    schema = UserSchema()
    errors = schema.validate(request.get_json())
    if errors:
        return jsonify({"error": "Invalid input"}), 400

    data = schema.load(request.get_json())
    existing_user = User.query.filter_by(username=data["username"]).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400

    new_user = User(data["username"], data["password"])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201


@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    schema = UserSchema(only=["username", "password"])
    errors = schema.validate(request.get_json())
    if errors:
        return jsonify({"error": "Invalid input"}), 400

    data = schema.load(request.get_json())
    user = User.query.filter_by(username=data["username"]).first()
    if not user or not ph.verify(data["password"], user.password):
        return jsonify({"error": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200


@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    return jsonify({"message": "Hello, protected world!"}), 200


if __name__ == "__main__":
    app.run(ssl_context="adhoc")