import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
from werkzeug.utils import secure_filename
import uuid
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import cloudinary
from cloudinary.uploader import upload
from dotenv import load_dotenv
from functools import wraps
import jwt
import bcrypt
from io import BytesIO
import base64
import requests  # For SMS API integration

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

CORS(app, 
     resources={
         r"/api/*": {
             "origins": ["http://localhost:8000"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"]
         }
     },
     supports_credentials=True)

# Cloudinary configuration
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET'),
    secure=True
)

# MongoDB configuration
client = MongoClient(
    os.getenv('MONGO_URI'),
    server_api=ServerApi('1'),
    connectTimeoutMS=30000,
    socketTimeoutMS=None,
    maxPoolSize=50
)
db = client.get_database('kredi_app')
users_collection = db.users
verification_codes_collection = db.verification_codes

# SMS Configuration (using Twilio as an example)
SMS_CONFIG = {
    'account_sid': os.getenv('TWILIO_ACCOUNT_SID'),
    'auth_token': os.getenv('TWILIO_AUTH_TOKEN'),
    'from_number': os.getenv('TWILIO_PHONE_NUMBER'),
    'api_url': 'https://api.twilio.com/2010-04-01/Accounts'
}

def send_sms(to_number, message):
    """Send SMS using Twilio API with better error handling"""
    try:
        # Clean and validate phone number
        to_number = ''.join(c for c in to_number if c.isdigit() or c == '+')
        if not to_number.startswith('+'):
            to_number = f"+234{to_number.lstrip('0')}"  # Example for Nigeria
        
        # Ensure we have a valid Twilio number
        from_number = SMS_CONFIG['from_number']
        if not from_number.startswith('+'):
            from_number = f"+{from_number}"
        
        # Prepare request
        url = f"{SMS_CONFIG['api_url']}/{SMS_CONFIG['account_sid']}/Messages.json"
        auth = (SMS_CONFIG['account_sid'], SMS_CONFIG['auth_token'])
        data = {
            'From': from_number,
            'To': to_number,
            'Body': message
        }
        
        # Make request
        response = requests.post(url, auth=auth, data=data)
        response.raise_for_status()
        
        print(f"📱 SMS sent to {to_number}")
        return True
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"Twilio API Error: {e.response.json().get('message', str(e))}"
        print(f"🔥 SMS failed to {to_number}: {error_msg}")
        return False
    except Exception as e:
        print(f"🔥 SMS failed to {to_number}: {str(e)}")
        return False
def generate_verification_code():
    return str(uuid.uuid4().int)[:6]

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_jwt_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.now(timezone.utc) + timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
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

@app.route('/api/send-otp', methods=['POST'])
@token_required
def send_otp(current_user):
    try:
        verification_code = generate_verification_code()
        
        # Store in MongoDB
        verification_codes_collection.insert_one({
            'user_id': current_user['_id'],
            'code': verification_code,
            'created_at': datetime.now(timezone.utc),
            'expires_at': datetime.now(timezone.utc) + timedelta(minutes=30),
            'sms_sent': False  # Track SMS status
        })
        
        # Send SMS
        sms_body = f"Your Kredi verification code: {verification_code}. Expires in 30 minutes."
        
        sms_sent = send_sms(
            current_user['phone'],
            sms_body
        )
        
        # Update SMS status in MongoDB
        verification_codes_collection.update_one(
            {'code': verification_code},
            {'$set': {'sms_sent': sms_sent}}
        )
        
        if not sms_sent:
            raise Exception("SMS service failed to send message")
            
        return jsonify({
            'success': True,
            'message': 'OTP sent successfully',
            'debug': {
                'phone': current_user['phone'],
                'code': verification_code
            }
        })
        
    except Exception as e:
        print(f"❗ OTP send error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to send OTP',
            'debug': str(e)
        }), 500

@app.route('/api/verify-otp', methods=['POST'])
@token_required
def verify_otp(current_user):
    try:
        code = request.json.get('code')
        if not code:
            return jsonify({'error': 'OTP code is required'}), 400
            
        verification = verification_codes_collection.find_one({
            'user_id': current_user['_id'],
            'code': code,
            'expires_at': {'$gt': datetime.now(timezone.utc)}
        })
        
        if not verification:
            return jsonify({'error': 'Invalid or expired OTP'}), 400
            
        users_collection.update_one(
            {'_id': current_user['_id']},
            {'$set': {'status': 'verified'}}
        )
        verification_codes_collection.delete_one({'_id': verification['_id']})
        
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    except Exception as e:
        app.logger.error(f"Error verifying OTP: {str(e)}")
        return jsonify({'error': 'Failed to verify OTP'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    data = request.form
    required_fields = ['first_name', 'last_name', 'email', 'phone', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
        
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'error': 'Email already registered'}), 409
    
    user_id = str(uuid.uuid4())
    user_data = {
        '_id': user_id,
        'first_name': data['first_name'],
        'middle_name': data.get('middle_name'),
        'last_name': data['last_name'],
        'email': data['email'],
        'phone': data['phone'],
        'password': hash_password(data['password']),
        'status': 'pending',
        'created_at': datetime.now(timezone.utc),
        'documents': [],
        'verification': None,
        'face_image': None
    }
    
    users_collection.insert_one(user_data)
    
    if 'face_image' in data and data['face_image']:
        result = upload_base64_image(
            data['face_image'],
            folder=f"kredi_app/{user_id}/face_recognition",
            public_id="face_image"
        )
        if result:
            users_collection.update_one(
                {'_id': user_id},
                {'$set': {'face_image': result['secure_url']}}
            )
    
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
                users_collection.update_one(
                    {'_id': user_id},
                    {'$push': {'documents': {
                        'public_id': result['public_id'],
                        'url': result['secure_url'],
                        'type': 'id_verification',
                        'uploaded_at': datetime.now(timezone.utc)
                    }}}
                )
            except Exception as e:
                app.logger.error(f"Document upload failed: {str(e)}")
    
    verification_code = generate_verification_code()
    verification_codes_collection.insert_one({
        'user_id': user_id,
        'code': verification_code,
        'created_at': datetime.now(timezone.utc),
        'expires_at': datetime.now(timezone.utc) + timedelta(minutes=30)
    })
    
    # Send SMS instead of email
    sms_body = f"Your Kredi verification code is: {verification_code}. Expires in 30 minutes."
    
    if not send_sms(data['phone'], sms_body):
        app.logger.error(f"Failed to send verification SMS to {data['phone']}")
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'token': generate_jwt_token(user_id),
        'message': 'Registration successful. Check your phone for verification code.'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
