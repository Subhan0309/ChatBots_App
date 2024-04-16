from functools import wraps
from flask import Flask ,jsonify,abort,request,current_app,render_template,redirect,url_for 
import models
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64encode, b64decode
import hashlib
import os
from models import User,user_sites 
import jwt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask_cors import CORS
from db import users_sites_collection




app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'secret_key'

#some helper functions


#middle ware jwt token authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            # print(token)
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data=jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = models.User.objects.get(id=data["user_id"])
            print(current_user.name)
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
            # if not current_user["active"]:
            #     abort(403)
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 500

        return f(current_user, *args, **kwargs)

    return decorated

# Encryption function
def encrypt(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

# Decryption function
def decrypt(key, ciphertext):
    iv = ciphertext[:16]  # Extract IV from the ciphertext
    ciphertext = ciphertext[16:]  # Remove IV from the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext



#routes

#home route

@app.route("/")
def landing_page():
    return "Hello landing page here"


@app.route("/dologin")
def return_login():
    return render_template("login.html")

@app.route("/home")
def return_home():
    # user_data = request.args.get('user_data')
    # Render home template with user data
    return render_template("home.html")


# Signup route
@app.route("/submit_signup", methods=["POST"])
def signup():
    try:
        data = request.form
        if not data:
            return {
                "message": "Please provide user details",
                "data": None,
                "error": "Bad request"
            }, 400
        
        # Check if email is already registered
        if User.objects(email=data.get('email')).first():
            return {
                "message": "Email already exists",
                "data": None,
                "error": "User Already registered"
            }, 409

        # Create new user
        new_user = User(
            name=data.get('name'),
            email=data.get('email'),
            password=generate_password_hash(data.get('password'))
        )
        new_user.save()

        return render_template("login.html")
    
    except Exception as e:
        return {
            "message": "Something went wrong",
            "error": str(e),
            "data": None
        }, 500

# Login route
@app.route("/submit_login", methods=["POST"])
def login():
    try:
        data = request.form
        if not data:
            return jsonify({
                "message": "Please provide user details",
                "error": "Bad request"
            }), 400
        
        # Find user by email
        user = User.objects(email=data.get('email')).first()
       
        if user and check_password_hash(user.password, data.get('password')):
            try:
                # token should expire after 24 hrs
                token = jwt.encode(
                    {"user_id": str(user.id)},
                    app.config["SECRET_KEY"],
                    algorithm="HS256"
                )
                # Construct user data in JSON serializable format
                user_data = {
                    "id": str(user.id),
                    "name": user.name,
                    "email": user.email,
                    "token": token
                }
                 # Redirect to home URL with user data
                return render_template("home.html",user_data=user_data)
            
            except Exception as e:
                return jsonify({
                    "error": "Something went wrong",
                    "message": str(e)
                }), 500
        return jsonify({
            "message": "Error fetching auth token!, invalid email or password",
            "error": "Unauthorized"
        }), 404

    except Exception as e:
        return jsonify({
            "message": "Something went wrong",
            "error": str(e)
        }), 500


@app.route("/submit_and_generateScript", methods=["POST"])
# calling middleware to authenticate the users
@token_required
def Generate_Script(current_user):
    try:

        data = request.json
        if data.get("url") and data.get("domain_name"):
            # Check if the URL is already stored for the current user
            # existing_record = user_sites.query.filter_by(user_id=current_user, site_url=data.get("url")).first()
            # if existing_record:
            #     # URL already exists, return the existing encryption key
            #     return jsonify({
            #         "message": "URL already exists for this user",
            #         "encryption_key": existing_record.key
            #     })

            # Generate encryption key using URL and domain name
            key_input = data.get("url") + data.get("domain_name")
            key = hashlib.sha256(key_input.encode('utf-8')).digest()

            # Encrypt the data
            plaintext = data.get("url").encode('utf-8')  # Convert data to bytes
            encrypted_data = encrypt(key, plaintext)

            # Store the encrypted data and key in the user_sites table
            new_record = user_sites(user_id=current_user,
                                    site_url=data.get("url"),
                                    key=b64encode(key).decode('utf-8'))
            new_record.save()

            # For decryption demonstration
            decrypted_data = decrypt(key, encrypted_data).decode('utf-8')  # Convert decrypted data to string
            print(decrypted_data)

            return jsonify({
                "message": "Encryption and decryption successful",
                "encryption_key": b64encode(key).decode('utf-8')  # Encode key to string format
            })
        else:
            return jsonify({
                "message": "Provide complete details please",
                "error": "Bad Request"
            }), 400

    except Exception as e:
        return jsonify({
            "message": "Something went wrong",
            "error": str(e)
        }), 500


@app.route("/view_history", methods=["GET"])

def view_history():
    user_id = "660c1120ae91c50c7707c661"  # Assuming the user ID is stored in the id attribute of the current_user object

    # Retrieve all records for the current user from the user_sites collection
    user_sites2 = users_sites_collection.find({"user_id": user_id})

    # Convert MongoDB cursor to list of dictionaries
    user_sites_list = list(user_sites2)

    # Return the list of user sites as JSON
    return jsonify({"user_sites": user_sites_list})

