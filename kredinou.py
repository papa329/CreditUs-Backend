import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
import uuid
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import cloudinary
from cloudinary.uploader import upload
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta

import jwt
import bcrypt
from io import BytesIO
import base64
from werkzeug.exceptions import HTTPException

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': os.getenv('SECRET_KEY'),
    'MAX_CONTENT_LENGTH': 5 * 1024 * 1024,
})

# Configure CORS
CORS(app, 
     resources={
         r"/api/*": {
             "origins": ["http://localhost:8000", "https://papa329.github.io"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True
         }
     })

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)

# MongoDB configuration
mongo_client = MongoClient(
    os.getenv('MONGO_URI'),
    server_api=ServerApi('1'),
    connectTimeoutMS=30000,
    socketTimeoutMS=None,
    maxPoolSize=50
)
db = mongo_client.get_database('kredi_app')
users_collection = db.users

# Utility Functions
def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Verify password against hashed version"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_jwt_token(user_id):
    """Generate JWT token with 1 day expiry"""
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """JWT token authentication decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        try:
            token = token.split(' ')[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'_id': data['user_id']})
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
        except Exception as e:
            return jsonify({'error': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

def upload_base64_image(base64_string, folder, public_id=None):
    """Upload base64 image to Cloudinary"""
    try:
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]
        file_obj = BytesIO(base64.b64decode(base64_string))
        result = upload(
            file_obj,
            folder=folder,
            public_id=public_id,
            resource_type="image",
            transformation=[
                {'width': 500, 'height': 500, 'crop': 'fill'},
                {'quality': 'auto'}
            ]
        )
        return result
    except Exception as e:
        app.logger.error(f"Cloudinary upload failed: {str(e)}")
        return None

# Error Handler
@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler"""
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint"""
    data = request.form
    
    # Validate required fields
    required_fields = ['first_name', 'last_name', 'email', 'phone', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
        
    # Check if email already exists
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'error': 'Email already registered'}), 409
    
    # Create user document
    user_id = str(uuid.uuid4())
    user_data = {
        '_id': user_id,
        'first_name': data['first_name'],
        'middle_name': data.get('middle_name'),
        'last_name': data['last_name'],
        'email': data['email'],
        'phone': data['phone'],
        'password': hash_password(data['password']),
        'status': 'active',  # Changed from 'pending' since we're not verifying
        'created_at': datetime.now(timezone.utc),
        'documents': [],
        'face_image': None
    }
    
    # Handle face image upload
    if 'face_image' in data and data['face_image']:
        result = upload_base64_image(
            data['face_image'],
            folder=f"kredi_app/{user_id}/face_recognition",
            public_id="face_image"
        )
        if result:
            user_data['face_image'] = result['secure_url']
    
    # Handle document upload
    if 'document' in request.files:
        file = request.files['document']
        if file.filename != '':
            try:
                result = upload(
                    file,
                    folder=f"kredi_app/{user_id}/documents",
                    resource_type="auto",
                    tags=["id_verification"]
                )
                user_data['documents'].append({
                    'public_id': result['public_id'],
                    'url': result['secure_url'],
                    'type': 'id_verification',
                    'uploaded_at': datetime.now(timezone.utc)
                })
            except Exception as e:
                app.logger.error(f"Document upload failed: {str(e)}")
    
    # Insert user into database
    users_collection.insert_one(user_data)
    
    # Generate and return JWT token
    token = generate_jwt_token(user_id)
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': user_id,
            'first_name': user_data['first_name'],
            'last_name': user_data['last_name'],
            'email': user_data['email'],
            'phone': user_data['phone']
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    # Validate required fields
    if not data or ('email' not in data and 'phone' not in data) or 'password' not in data:
        return jsonify({'error': 'Please provide either email or phone and password'}), 400
    
    # Find user by email or phone
    query = {'email': data['email']} if 'email' in data else {'phone': data['phone']}
    user = users_collection.find_one(query)
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not check_password(data['password'], user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Update last login time
    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'last_login': datetime.now(timezone.utc)}}
    )
    
    # Generate and return JWT token
    token = generate_jwt_token(user['_id'])
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': str(user['_id']),
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email'],
            'phone': user['phone']
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
