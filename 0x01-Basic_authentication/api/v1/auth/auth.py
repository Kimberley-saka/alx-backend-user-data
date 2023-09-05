#!/usr/bin/env python3
"""
authentication system
"""
from flask import request
from typing import List, TypeVar


class Auth():
    """
    auth
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require path
        """
        if path is None or (excluded_paths is None or len(excluded_paths) ==
                            0):
            return True
        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            if not excluded_path.endswith('/'):
                excluded_path += '/'

            if path.startswith(excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Validate all requests to secure the API
        """
        if request is None:
            return None
        
        auth_key = request.headers.get("Authorization")

        if auth_key is None:
            return None
        return auth_key

    def current_user(self, request=None) -> TypeVar('User'):
        """
        doc
        """
        return None
