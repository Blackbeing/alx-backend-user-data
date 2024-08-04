#!/usr/bin/env python3
"""This module provides function to filter out sensitive data"""

import logging
import re
from typing import List

PII_FIELDS = (
    "name",
    "email",
    "phone",
    "ssn",
    "password",
)


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


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        self.fields: List[str] = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """Format record to redact sensitive data"""
        msg = filter_datum(self.fields, self.REDACTION, record.msg,
                           self.SEPARATOR)
        record.msg = msg
        return super().format(record)


def get_logger() -> logging.Logger:
    """Return a logger that writes to stdout with redacted PII."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    sh = logging.StreamHandler()
    sh.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(sh)
    return logger
