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
