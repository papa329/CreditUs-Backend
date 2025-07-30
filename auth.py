from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import cloudinary.uploader
from bson.objectid import ObjectId
import re
from utils.email import send_verification_email, generate_verification_code

auth_bp = Blueprint('auth', __name__)

# Helper functions
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

def validate_phone(phone):
    return phone.startswith('509') and len(phone) == 11 and phone.isdigit()

# Routes
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.form
    files = request.files
    
    # Validate required fields
    required_fields = ['nom', 'prenom', 'email', 'phone', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Validate email and phone
    if not validate_email(data['email']):
        return jsonify({"error": "Invalid email format"}), 400
    
    if not validate_phone(data['phone']):
        return jsonify({"error": "Invalid phone number. Must be 509XXXXXXXX"}), 400
    
    # Check if user already exists
    mongo = current_app.extensions['mongo']
    if mongo.db.users.find_one({"email": data['email']}):
        return jsonify({"error": "Email already registered"}), 400
    
    if mongo.db.users.find_one({"phone": data['phone']}):
        return jsonify({"error": "Phone number already registered"}), 400
    
    # Handle document uploads
    document_urls = []
    for file_key in files:
        file = files[file_key]
        if file.filename == '':
            continue
            
        try:
            upload_result = cloudinary.uploader.upload(file, folder="kredi_app/documents")
            document_urls.append({
                "url": upload_result['secure_url'],
                "public_id": upload_result['public_id'],
                "type": data.get(f"{file_key}_type", "other")
            })
        except Exception as e:
            return jsonify({"error": f"Document upload failed: {str(e)}"}), 500
    
    # Handle face image
    face_image = None
    if 'face_image' in files:
        try:
            upload_result = cloudinary.uploader.upload(
                files['face_image'], 
                folder="kredi_app/face_images"
            )
            face_image = upload_result['secure_url']
        except Exception as e:
            return jsonify({"error": f"Face image upload failed: {str(e)}"}), 500
    
    
    verification_code = generate_verification_code()
    
    # Create user
    user_data = {
        "nom": data['nom'],
        "prenom": data['prenom'],
        "email": data['email'],
        "phone": data['phone'],
        "password": generate_password_hash(data['password']),
        "documents": document_urls,
        "face_image": face_image,
        "verified": False,
        "verification_code": verification_code
    }
    
    try:
        # Save user to database
        result = mongo.db.users.insert_one(user_data)
        
        # Send verification email
        if not send_verification_email(data['email'], verification_code):
            # Rollback user creation if email fails
            mongo.db.users.delete_one({"_id": result.inserted_id})
            return jsonify({"error": "Failed to send verification email"}), 500
        
        return jsonify({
            "message": "Registration successful. Please check your email for verification.",
            "user_id": str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500

# ... (keep existing login and verify routes unchanged)
