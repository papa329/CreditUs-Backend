import os
class Config:
    # Cloudinary Configuration
    CLOUDINARY_CLOUD_NAME = "dtgtadxgq"
    CLOUDINARY_API_KEY = "725813336421935"
    CLOUDINARY_API_SECRET = "ZAEcNd5qQ2KGtgbSTrlMscm9cnA"
    
    # MongoDB Configuration
    MONGO_URI = "mongodb+srv://D45192091425Ea:D45192091425Ea@cluster0.kdsxlk6.mongodb.net/kredi_app?retryWrites=true&w=majority"
    
    # Flask Secret Key
    SECRET_KEY = "your-secret-key-here"
    
    # Brevo SMTP Configuration
    BREVO_SMTP_SERVER = "smtp-relay.brevo.com"
    BREVO_SMTP_PORT = 587
    BREVO_SMTP_LOGIN = "9370fc001@smtp-brevo.com"
    BREVO_SMTP_PASSWORD = "91C5SMdRfVTYLQ7X"
    BREVO_SENDER_EMAIL = "noreply@kredi.ht"
    BREVO_SENDER_NAME = "Kredi App"
    
    # SMS Configuration (Twilio)
    SMS_CONFIG = {
    'account_sid': os.getenv('TWILIO_ACCOUNT_SID'),
    'auth_token': os.getenv('TWILIO_AUTH_TOKEN'),
    'from_number': os.getenv('TWILIO_PHONE_NUMBER'),  # Must be E.164 format
    'api_url': 'https://api.twilio.com/2010-04-01/Accounts'
}
