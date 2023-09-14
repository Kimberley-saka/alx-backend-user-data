#!/usr/bin/env python3
""""
Create passoword hash
"""
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """
    password hash
    """
    salted_hash = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salted_hash)
    return hashed_password


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        add new user
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user is not None:
                raise ValueError(f"User {email} already exists")

        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)

            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        tries to locate user by email
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return bcrypt.checkpw(
                        password.encode('utf-8'), user.hashed_password)
            return False
        except NoResultFound:
            return False
