#!/usr/bin/env python3
""""
Create passoword hash
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    password hash
    """
    salted_hash = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salted_hash)
    return hashed_password
