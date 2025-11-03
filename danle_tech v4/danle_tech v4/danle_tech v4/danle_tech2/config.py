import os
from dotenv import load_dotenv
load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'port': int(os.getenv('DB_PORT', 3406)),
    'password': os.getenv('DB_PASS', ''),
    'database': os.getenv('DB_NAME', 'danle_tech'),
    'autocommit': True
}

SECRET_KEY = os.getenv('SECRET_KEY', '1234')
