#!/usr/bin/env python3
""""
Create passoword hash
"""
import bcrypt
import uuid
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


def _generate_uuid() -> str:
    """
    uuid
    """
    new_id = uuid.uuid4()
    return str(new_id)


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

    def create_session(self, email: str) -> str:
        """
        sessions
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            user.session_id = _generate_uuid()
            return user.session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        get user
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return user

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy session
        """
        user = self._db.find_user_by(id=user_id)
        if user:
            user.session_id = None
            self._db.update_user(user)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        reset
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
            return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        update
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            user.hashed_password = _hash_password(password)
            user.reset_token = None
            return None
        except NoResultFound:
            raise ValueError
