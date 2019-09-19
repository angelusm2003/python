from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Downloads/providers.db'

db = SQLAlchemy(app)

class Providers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    phonenumber = db.Column(db.Integer)
    language = db.Column(db.String(50))
    currency = db.Column(db.String(5))
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'access_tok' in request.headers:
            token = request.headers['access_tok']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current = Providers.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is invalid'}), 401

        return f(current, *args, **kwargs)

    return decorated

@app.route('/providers', methods=['GET'])
@token_required
def get_all_providers(current):

    providers = Providers.query.all()

    output = []

    for providers in providers:
        providers_data = {}
        providers_data['email'] = providers.email
        providers_data['name'] = providers.name
        providers_data['phonenumber'] = providers.phonenumber
        providers_data['currency'] = providers.currency
        providers_data['language'] = providers.language
        output.append(providers_data)

    return jsonify({'providers' : output})

@app.route('/providers/<email>', methods=['GET'])
@token_required
def get_one_provider(current, email):

    providers = Providers.query.filter_by(email=email).first()

    if not providers:
        return jsonify({'message' : 'No mail found'})

    providers_data = {}
    providers_data['email'] = providers.email
    providers_data['name'] = providers.name
    providers_data['phonenumber'] = providers.phonenumber
    providers_data['currency'] = providers.currency
    providers_data['language'] = providers.language
                    
    return jsonify({'providers' : providers_data})

@app.route('/providers', methods=['POST'])
@token_required
def create_providers(current):
    
    data = request.get_json()
    new_provider = Providers(email=str(uuid.uuid4()), name=data['name'], phonenumber=data['phonenumber'], 
                    currency=data['currency'], language=data['language'])
    db.session.add(new_provider)
    db.session.commit()

    return jsonify({'message' : 'New provider created'})

@app.route('/providers/<email>', methods=['PUT'])
@token_required
def find_providers(current, email):
    
    providers = Providers.query.filter_by(email=email).first()

    if not providers:
        return jsonify({'message' : 'No provider found'})

    db.session.commit()

    return jsonify({'message' : 'The provider has been found'})

@app.route('/providers/<email>', methods=['DELETE'])
@token_required
def delete_provider(current, email):
    
    providers = Providers.query.filter_by(email=email).first()

    if not providers:
        return jsonify({'message' : 'No provider found'})

    db.session.delete(providers)
    db.session.commit()

    return jsonify({'message' : 'The provider was deleted'})

if __name__ == '__main__':
    app.run(debug=True)