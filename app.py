import os
from flask import Flask, request, jsonify, make_response
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'

users_db = {}


def generate_token(user_id):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token = jwt.encode({
        'sub': user_id,
        'exp': expiration_time
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users_db:
        return jsonify({"message": "User already exists"}), 400

    users_db[username] = {
        'password': password
    }

    return jsonify({"message": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users_db.get(username)

    if not user or user['password'] != password:
        return jsonify({"message": "Invalid credentials"}), 401

    token = generate_token(username)
    return jsonify({'token': token})


@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    token = request.cookies.get('jwt')
    if not token:
        return jsonify({"message": "No JWT token found!"}), 400

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return jsonify(decoded_token)
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"message": "JWT token is missing"}), 400

    response = make_response(jsonify({"message": "JWT token set successfully!"}))
    response.set_cookie('jwt', token, httponly=True, secure=True, samesite='Strict')
    return response


if __name__ == '__main__':
    app.run(debug=True)