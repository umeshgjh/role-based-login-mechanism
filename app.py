from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Replace with a secure key in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'
    dob = db.Column(db.String(10), nullable=True)
    department = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(50), nullable=True)

# Initialize the database
#@app.before_first_request
#def create_tables():
#    db.create_all()

# Register a new user (Admin only in real scenarios)
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        username=data['username'],
        password=hashed_password,
        role=data['role'],
        dob=data.get('dob'),
        department=data.get('department'),
        location=data.get('location')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

# Login endpoint to authenticate users
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token)
    return jsonify({'message': 'Invalid credentials'}), 401

# Admin endpoint to view details of all users
@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'message': 'Access forbidden: Admins only'}), 403

    users = User.query.all()
    user_data = [{'username': user.username, 'dob': user.dob, 'department': user.department, 'location': user.location} for user in users]
    return jsonify(user_data), 200

# Regular user endpoint to view their own profile details
@app.route('/user/profile', methods=['GET'])
@jwt_required()
def user_profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = {
        'username': user.username,
        'dob': user.dob,
        'department': user.department,
        'location': user.location
    }
    return jsonify(user_data), 200

# Error handler for 404 errors
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

# Error handler for other exceptions
@app.errorhandler(Exception)
def handle_exception(error):
    return jsonify({'message': 'An error occurred', 'details': str(error)}), 500

if __name__ == '__main__':
    app.run(debug=True)
