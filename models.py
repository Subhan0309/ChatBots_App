from db import db


class User(db.Document):
    name = db.StringField()
    email = db.EmailField(unique=True, required=True)
    password = db.StringField(required=True)

class user_sites(db.Document):
    user_id = db.ReferenceField(User)  # Reference to the User table
    site_url = db.StringField()
    key = db.StringField()
