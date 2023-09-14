#!/usr/bin/env python3
"""
basic app
"""
from flask import Flask, jsonify, request, abort
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def basic_app():
    """
    basic
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """"
    register new user
    """
    try:
        email = request.form.get('email')
        password = request.form.get('password')

        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'] strict_slashes=False)
def login():
    """
    login
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not (AUTH.valid_login(email, password)):
        abort(401)

    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie('session_id', session_id)

    return response


@app.route('/sessions', methods['DELETE'])
def logout():
    """
    Logout
    """
    cookie = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(cookie)
    if user is None:
        abort(403)
    else:
        AUTH.destroy_session(user.id)
        return redirect('/')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
