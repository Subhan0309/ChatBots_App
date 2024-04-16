from pymongo import MongoClient
from flask import Flask
from flask_mongoengine import MongoEngine



# MongoDB Configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['ChatBots']
users_collection = db['Users']
users_sites_collection=db['users_sites']


# Create Flask app instance
app = Flask(__name__)

# Configure Flask app for MongoDB
app.config['MONGODB_SETTINGS'] = {
    'db': 'ChatBots',
    'host': 'localhost',
    'port': 27017
}

# Initialize Flask-MongoEngine
db = MongoEngine(app)
