#!/usr/bin/enauth_v python3
"""
Basic authentication
"""
from auth import Auth
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
    Decode auth_value of a Base64 string base64_authorization_header
    """
    if base64_authorization_header is None or not isinstance(
         base64_authorization_header, str):
        return None

    try:
        auth_value = base64_authorization_header.encode('utf-8')
        decoded_auth_value = base64.b64decode(auth_value)
        return decoded_auth_value.decode('utf-8')
    except Exception:
        return None
