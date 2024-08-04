#!/usr/bin/env python3
"""This module provides function to filter out sensitive data"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""

    SALT = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), SALT)
