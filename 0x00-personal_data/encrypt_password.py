#!/usr/bin/env python3
"""This module provides function to filter out sensitive data"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""

    SALT = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), SALT)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if the password is valid by comparing it to the
    hashed password.
    """
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
