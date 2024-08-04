#!/usr/bin/env python3
"""This module provides function to filter out sensitive data"""

import re
from typing import List


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Redact sensitive data from a message.

    This function takes a list of fields to redact, a redaction string to
    replace the sensitive data with, a message to redact, and a separator
    string. It then uses a regular expression to find and replace all
    occurrences of the specified fields in the message with the redaction
    string.

    Args:
        fields (List[str]): A list of fields to redact.
        redaction (str): The string to replace sensitive data with.
        message (str): The message to redact.
        separator (str): The separator between the field and sensitive data.

    Returns:
        str: The redacted message.
    """
    pattern = re.compile(f"({'|'.join(fields)})=(.*?{separator})")
    filtered = re.sub(pattern, f"\\1={redaction}{separator}", message)
    return filtered
