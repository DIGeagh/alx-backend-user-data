#!/usr/bin/env python3
"""
Module for filtering sensitive information from log records.
"""

import logging
import re
import mysql.connector
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields: A list of fields to redact.
        redaction: The redaction text.
        message: The log message.
        separator: The field separator in the log message.

    Returns:
        A string with specified fields redacted.
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
    Formatter class for redacting sensitive information from log messages.
    """

    REDACTION = "***"
    FORMAT = "[USER] %(name)s %(levelname)s %(asctime)s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with redacted sensitive fields.

        Args:
            record: The log record to format.

        Returns:
            The formatted and redacted log message.
        """
        record.msg = filter_datum(self.fields, self.REDACTION, record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger with sensitive data redaction.

    Returns:
        A configured logger instance.
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
    Establishes and returns a secure database connection.

    Returns:
        A MySQLConnection object connected to the database.
    """
    return mysql.connector.connect(
        user="username",
        password="password",
        host="localhost",
        database="user_data"
    )


def main() -> None:
    """
    Retrieves user data from the database and logs it with redacted fields.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    logger = get_logger()

    for row in cursor:
        message = "; ".join(f"{column}: {value}" for column, value in zip(cursor.column_names, row))
        logger.info(message)

    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
