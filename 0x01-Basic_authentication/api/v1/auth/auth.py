#!/usr/bin/env python3
"""
This module provides authentication functions.
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
    A utility class for handling authentication functions.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if the given path requires authentication.
        path(str) : The request path that needs to be checked.
        excluded_paths (List[str]) : A list of paths that do not require
        authentication.

        Returns (bool): Returns True if the path requires authentication,
        False otherwise.
        """
        if path and not path.endswith("/"):
            path = f"{path}/"

        if path is None or not excluded_paths or path not in excluded_paths:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the 'Authorization' header from the given request
        if present.

        Returns (str): The 'Authorization' header value if present, None
        otherwise.
        """
        if request is None or not request.headers.get('Authorization'):
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Placeholder method to retrieve the current user based on the given
        request.
        """
        return None
