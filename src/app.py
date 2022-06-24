import os, re, random, string, requests
from datetime import datetime, timedelta
import jwt
import fnmatch
from functools import wraps
from flask import Flask, jsonify, request, make_response
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
#from decouple import config

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ab0534175bdf5a6a0cbbdb41c9239bc6'
app.config.from_object('config.Config')
#app.config['SQLALCHEMY_DATABASE_URI'] = config('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] =  'postgresql://postgres:postgres@db-container-bmg:5432/pg_backend'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app,db)
cache = Cache(app)

from models import *

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

'''
1. Create an endpoint for Registration Page, 
must include following field and validation. 
'''
@app.route('/players', methods=['POST'])
def create_player():
    body        = request.get_json()
    uname       = body['username']
    passwd      = body['password']
    name        = body['name']
    mail        = body['email']
    ref_code    = body['referral_code']
    
    #generate referral code if referral code is not provided
    if ref_code == '':
        ref_code =  ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
    
    #hashed password account
    hashed_password = generate_password_hash(passwd, method='sha256')
    
    if(re.fullmatch(regex_mail, mail)):
        #checking for existing user
        if db.session.query(db.exists().where(Account.mail == mail)).scalar():
            return "invalid field information"
        #generate public_id
        gencode = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 20))    
        account = Account(
            public_id = str(gencode),
            uname=uname, 
            passwd=hashed_password, 
            name=name, 
            mail=mail, 
            ref_code=ref_code
        )
        #db.session.add(Account(uname=uname, passwd=hashed_password, name=name, mail=mail, ref_code=ref_code))
        db.session.add(account)
        db.session.commit()
        return "ok"
    else:
        return "invalid field information"

@app.route('/players', methods=['GET'])
@cache.cached(timeout=30, query_string=True)
def get_players():
    players = []
    for item in db.session.query(Account).all():
        del item.__dict__['_sa_instance_state']
        players.append(item.__dict__)
    return jsonify(players)

'''
2. Create an endpoint for login.
Input:  username and password 
{
"username": "anubiazo",
"password": "anubiaz123!!"
}
Output: user data and token

'''
@app.route('/login', methods=['POST'])
def login_player():
    auth        = request.get_json()
    uname       = auth['username']
    passwd      = auth['password']
    
    if not auth or not uname or not passwd:
        # returns Could not verify if any email or / and password is missing
        #return 'Login required !!'
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    
    user = db.session.query(Account).filter(Account.uname==uname).first()
    if not user:
        return make_response(
            f'Could not verify user {uname}',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    
    player = []
    for item in db.session.query(Account).filter(Account.uname==uname):
        del item.__dict__['_sa_instance_state']
        player.append(item.__dict__)
    if check_password_hash(user.passwd, passwd):
        # generates the JWT Token
        #token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        token = jwt.encode({
            'public_id' : user.public_id, 
            'exp' : datetime.utcnow() + timedelta(minutes=30)
            }, app.config['SECRET_KEY'], "HS256")
        
        
        player.append({'token': token})
        return make_response(jsonify(player), 201)
        #return make_response(jsonify(player), 201)
    
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )
    
'''
3. Create an endpoint to edit your data.
Input:  New data (need to be revalidated) and token 
Output: Unauthorized message if token is wrong/empty,
        updated data if pass validation, else invalid field information.
'''       
@app.route('/update-player/<player_id>', methods=['PUT'])
@token_required
def update_player(current_user, player_id):
    body        = request.get_json()
    uname       = body['username']
    passwd      = body['password']
    name        = body['name']
    mail        = body['email']
    
    
    #hashed password account
    hashed_password = generate_password_hash(passwd, method='sha256')
    
    if(re.fullmatch(regex_mail, mail)):
        db.session.query(Account).filter(Account.id==player_id, Account.public_id==current_user.public_id).update(
            dict(uname=uname, passwd=hashed_password, name=name, mail=mail))
        # db.session.query(Account).filter(Account.public_id==current_user.public_id, Account.uname==str(username)).update(
        #     dict(uname=uname, passwd=hashed_password, name=name, mail=mail))
        db.session.commit()
        return 'updated data'
    else:
        return "invalid field information"
    
'''
4. Create an endpoint for ref-code input.
Input: referral code and token
Output: Unauthorized message if token is wrong/empty,
Ok if ref-code is correct, else invalid information.

POST /check-refcode HTTP/1.1
HOST: localhost:5000
content-type: application/json
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJHVUU1SU0zUVlDWlZHS0RVMzdGQyIsImV4cCI6MTY1NDY3NTcyMn0.oM1RGN4fzeZMlFa620FwUWRCo-Rta6uo8Pki5BKKlC8
content-length: 34

{
"referral_code":"QGO2B20T93"
}
'''       
@app.route('/check-refcode', methods=['POST'])
@token_required
def check_refcode(current_user):
    body        = request.get_json()
    ref_code    = body['referral_code']
    
    if db.session.query(Account).filter(Account.ref_code == ref_code).first():
        return "ok"

'''
5. Create an endpoint to find user by name. 
Input:  name.
{
"name":"anubiazo"
}
Output: list of matched user.
''' 
@app.route('/player', methods=['POST'])
@cache.cached(timeout=30, query_string=True)
def get_player():
    body        = request.get_json()
    name        = body['name']
    player = []
    for item in db.session.query(Account).filter(Account.name==name):
        del item.__dict__['_sa_instance_state']
        player.append(item.__dict__)
    return jsonify(player)

'''
6. Create and endpoint to get single random hero based on input from this endpoint:
https://ddragon.leagueoflegends.com/cdn/6.24.1/data/en_US/champion.json
Input   : partial name of hero. 
{
    "keyword":"Rek"
}
Output  : single hero details.
''' 
@app.route('/player-lol', methods=['POST'])
@token_required
@cache.cached(timeout=5, query_string=True)
def get_player_lol(current_user):
    body        = request.get_json()
    keyword     = body['keyword']
    API_URL     = "https://ddragon.leagueoflegends.com/cdn/6.24.1/data/en_US/champion.json"
    req_data    = requests.get(API_URL)
    lol_data    = (req_data.json()).get('data')
    filter_data = fnmatch.filter(lol_data, f'{keyword}*')
    result      = lol_data.get(filter_data[0])
    return jsonify(keyword,result)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)