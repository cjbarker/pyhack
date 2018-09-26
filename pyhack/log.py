#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Logging utility for managing output handlers such as format, type, and streams."""

import sys
import logging
from logging.handlers import TimedRotatingFileHandler

FORMATTER = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
LOG_FILE = "pyhack.log"

def get_console_handler():
    """Creates a STDOUT stream handler for the console with appropriate formatting.

    :returns:   stream hander to STDOUT aka the console.
    :rtye: logging.StreamHandler
    """
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler

def get_file_handler(file_name=LOG_FILE):
    """Creates time based rotating log file handler.

    :param file_name: name of log file to create for handler
    :type file_name: str
    :returns: logging for file rotation
    :rtype: TimeRotatingFileHandler
    """
    file_handler = TimedRotatingFileHandler(file_name, when='midnight')
    file_handler.setFormatter(FORMATTER)
    return file_handler

def get_logger(logger_name, logging_level=logging.DEBUG, rotate_file=False):
    """Creates a logger for a given name while apply default handler for console and rotating file.

    :param logger_name: name of the logger
    :type logger_name: str
    :param logging_level: level to log statements at: DEBUG, INFO, WARN, ERROR.
    :type logging_level: logging.DEBUG
    :param rotate_file: denote if should create rotating time based file.
    :type rotate_file: bool
    :returns: logger created based on appropriate parameters for initialization
    :rtype: logging.logger
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging_level)
    logger.addHandler(get_console_handler())
    if rotate_file:
        logger.addHandler(get_file_handler())
    logger.propagate = False    # rarely necessary to propage the error up to parent
    return logger
