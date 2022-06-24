import os, re, random, string, requests
from datetime import datetime, timedelta
import jwt
from functools import wraps
from flask import Flask, jsonify, request, make_response
#from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restful import Resource, Api
from flask_cors import CORS
from decouple import config

app = Flask(__name__)

# inisiasai objek flask restful
api = Api(app)

# inisiasi object flask cors
CORS(app)

app.config['SECRET_KEY'] = config('SECRET_KEY')
#app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://postgres:postgres@db-container-bmg:5432/pg_backend'
app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#cache = Cache(app)
app.config["CACHE_TYPE"] = "null"

# inisiasi class models
from models import *

# mencreate database
db.create_all()

#regex phrases for email
regex_mail = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'})
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = db.session.query(Account).filter(Account.public_id==data['public_id']).first()
        except:
            return jsonify({
                'message' : 'invalid field information!!'
            })
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)

    return decorated

class Players(Resource):
    def get(self):
        query = db.session.query(Account).all()
        players = [
            {
                "id": data.id,
                "username": data.uname,
                "name": data.name,
                "email": data.email,
                "referal_code": data.ref_code

            }
            for data in query
        ]
        response = {
            "code" : 200, 
            "msg"  : "Query data sukses",
            "data" : players
        }

        return response, 200

    def post(self): 
        body        = request.get_json()
        uname       = body['username']
        passwd      = body['password']
        name        = body['name']
        email       = body['email']
        ref_code    = body['referral_code']

        #generate random referral code
        if ref_code == "":
            ref_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
        
        #hashed password account
        hashed_password = generate_password_hash(passwd, method='sha256')

        if(re.fullmatch(regex_mail, email)):
            #checking for existing user by email
            if db.session.query(db.exists().where(Account.email == email)).scalar():
                return "invalid field information"
            #generate public_id
            gencode = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 20))    
            account = Account(
                public_id = str(gencode),
                uname=uname, 
                passwd=hashed_password, 
                name=name, 
                email=email, 
                ref_code=ref_code
            )
            account.save()
            # db.session.add(account)
            # db.session.commit()

            response = {
                "msg" : "Data insert successful",
                "code": 200
            }

            return response, 200
            
        else:
            return "invalid field information"

@app.route('/')
def hello_world():
    statement = 'Hello World!'
    return statement

# inisialisasi url / api 
# testing
api.add_resource(Players, "/api", methods=["GET", "POST"])

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
    #app.run(debug=True, port=5005)