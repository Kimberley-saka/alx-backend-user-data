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
        doc
        """
        return False

    def authorization_header(self, request=None) -> str:
        """
        doc
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        doc
        """
        return None
