#!/usr/bin/env python3
"""
This module provides basic authentication functions.
"""

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar


class BasicAuth(Auth):
    """
    A utility class for handling basic authentication functions.
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the base64-encoded part of the Authorization
        header for basic authentication.

        Returns (str): The base64-encoded part of the Authorization
        header, None otherwise.
        """
        if not (authorization_header
                and isinstance(authorization_header, str)):
            return None
        prefix = "Basic "
        if not authorization_header.startswith(prefix):
            return None
        return authorization_header[len(prefix):]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes a base64-encoded string.

        Returns (str): The decoded string, None otherwise.
        """
        if not (base64_authorization_header
                and isinstance(base64_authorization_header, str)):
            return None
        try:
            return base64.b64decode(base64_authorization_header,
                                    validate=True).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the user credentials from the base64-encoded
        authorization header.

        Returns (str, str): The email and password, None otherwise.
        """
        if not (decoded_base64_authorization_header
                and isinstance(decoded_base64_authorization_header, str)):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        # split on first colon
        credentials = decoded_base64_authorization_header.split(':', 1)
        return credentials

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on his email and password.
        """
        if not (user_email and isinstance(user_email, str) and user_pwd
                and isinstance(user_pwd, str)):
            return None
        try:
            from models.user import User
            user_records = User.search({"email": user_email})
            if not user_records:
                return None
            else:
                user = user_records[0]
                if user.is_valid_password(user_pwd):
                    return user
                else:
                    return None
        except Exception:
            return None
