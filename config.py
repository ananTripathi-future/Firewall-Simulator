import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, 'rules.json')
EXPORT_DIR = os.path.join(BASE_DIR, 'exports')

# Ensure directories exist
os.makedirs(EXPORT_DIR, exist_ok=True)

# Web Server Settings
HOST = '127.0.0.1'
PORT = 5000
MAX_LOG_HISTORY = 100
