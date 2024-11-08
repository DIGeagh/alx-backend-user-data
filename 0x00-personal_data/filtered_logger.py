#!/usr/bin/env python3
"""
Module for filtering sensitive information from log records.
"""

import logging
import re
import mysql.connector
from typing import List

# Fields that need redaction in logs
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Redact specified fields in a message.

    Args:
        fields (List[str]): Fields to redact.
        redaction (str): Redaction text.
        message (str): Original log message.
        separator (str): Field separator in the log message.

    Returns:
        str: Message with redacted fields.
    """
    for field in fields:
        message = re.sub(
            rf"(?<={field}{separator})(.*?)(?={separator})",
            redaction,
            message
        )
    return message


class RedactingFormatter(logging.Formatter):
    """
    Formatter class to redact sensitive information from log messages.
    """

    REDACTION = "***"
    FORMAT = "[USER] %(name)s %(levelname)s %(asctime)s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]) -> None:
        """
        Initializes the formatter with fields to redact.

        Args:
            fields (List[str]): List of fields to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with redacted sensitive fields.

        Args:
            record (logging.LogRecord): Log record to format.

        Returns:
            str: Formatted and redacted log message.
        """
        record.msg = filter_datum(self.fields, self.REDACTION, record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """
    Set up a logger for user data with sensitive fields redacted.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establishes a connection to the database.
