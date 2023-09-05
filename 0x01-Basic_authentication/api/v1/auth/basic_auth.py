#!/usr/bin/env python3
"""
Basic authentication
"""
from api.v1.auth.auth import Auth
import base64


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
    Returns the user email and password from the Base64 decoded value
    """
    if decoded_base64_authorization_header is None:
        return (None, None)

    if not isinstance(decoded_base64_authorization_header, str):
        return (None, None)

    if ':' not in decoded_base64_authorization_header:
        return (None, None)

    email, password = decoded_base64_authorization_header.split(':', 1)
    return (email, password)
