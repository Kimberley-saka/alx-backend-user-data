#!/usr/bin/env python3
"""
Basic authentication
"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """
    basic auth
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization header
        for a Basic Authentication
        """
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split("Basic ")[1]


def decode_base64_authorization_header(
          self, base64_authorization_header: str) -> str:
    """
    Decode value of a Base64 string base64_authorization_header
    """
    if base64_authorization_header is None or not isinstance(
         base64_authorization_header, str):
        return None

    try:
        decoded_data = base64.b64decode(base64_authorization_header)
        return decoded_data.decode('utf-8')
    except Exception:
        return None


def extract_user_credentials(
        self, decoded_base64_authorization_header: str) -> (str, str):
    """
    Returns the user email and password from the Base64 decoded_val value
    """
    if decoded_base64_authorization_header is None:
        return (None, None)

    if not isinstance(decoded_base64_authorization_header, str):
        return (None, None)

    if ':' not in decoded_base64_authorization_header:
        return (None, None)

    email, password = decoded_base64_authorization_header.split(':', 1)
    return (email, password)


def user_object_from_credentials(self, user_email: str,
                                 user_pwd: str) -> TypeVar('User'):
    """
    doc
    """
    if user_email is None or not isinstance(user_email, str):
        return None

    if user_pwd is None or not isinstance(user_pwd, str):
        return None
    user_list = User.search({"email": user_email})

    if not user_list:
        return None

    for user in user_list:
        if user.is_valid_password(user_pwd):
            return user

    return None


def current_user(self, request=None) -> TypeVar('User'):
    """
    Piecing it all together
    """
    authorization_header = self.authorization_header(request)
    if authorization_header is not None:
        value = self.extract_base64_authorization_header(authorization_header)
        if value is not None:
            decoded_val = self.decode_base64_authorization_header(value)
            if decoded_val is not None:
                email, password = self.extract_user_credentials(decoded_val)
                if email is not None:
                    return self.user_object_from_credentials(
                        email, password)

    return
