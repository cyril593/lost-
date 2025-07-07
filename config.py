import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql+pymysql://root:@localhost/lost_and_found_database'  
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Corrected UPLOAD_FOLDER path for consistency
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 # 16MB upload limit
    # Updated MODEL_PATH for PyTorch model
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'static', 'model', 'item_classifier.pt')
    MAIL_SERVER = 'smtp.yourprovider.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-email@example.com'
    MAIL_PASSWORD = 'your-email-password'
    MAIL_DEFAULT_SENDER = 'noreply@lostandfound.example.com'
    
    
    CLAIM_REVIEW_DAYS = 7 
    CLAIM_RESPONSE_DAYS = 3  