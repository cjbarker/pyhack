#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""portscan provides functionality to apply various network port scanning techniques to a given IP address and
port."""

from __future__ import print_function
from enum import Enum

import logging
import sys
import socket

import pyhack.log as log

# Globals
MIN_PORT = 1
MAX_PORT = 65535
LOGGER = log.get_logger("portscan")

class ScanType(Enum):
    """Port scan types defined and supported.

        ALL - Indicates ALL types of port scans.

        PING - Indicates a PING aka ICMP UDP scan.

        HALF_OPEN - Indicates a half open aka TCP SYNC scan.

        CONNECT - Indicates a full connect TCP Connect scan.

        NULL - Indicates a null flag packet TCP scan.

        FIN - indicates a FIN flag packet TCP scan.

        XMAS - indicates all FULL flag packet TCP scan.
    """
    ALL = 1
    PING = 2
    HALF_OPEN = 3
    CONNECT = 4
    NULL = 5
    FIN = 6
    XMAS = 7

def resolve_hostname(host=None):
    """Leverages socket to IP address for a given hostname. If already IP address resolve ignored.

    :param: hostname to resolve
    :type: str
    :return: IP address of resolved hostname
    :rtype: str
    :raise: socket.gaierror if fails to resolve host
    """
    if valid_ip(host):
        return host
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror, e:
        LOGGER.warn("Unable to resolve hostname: " + host)
        raise e

def valid_port(port=0):
    """Validates if given network port number is valid for use.

    :param: port number to validate
    :type: int
    :return: denotes true if port falls within valid range check
    :rtype: bool
    """
    return (port >= MIN_PORT and port <= MAX_PORT)

def ping_scan(host=None, port=0):
    pass

def half_open_scan(host=None, port=0):
    pass

def connect_scan(host=None, port=0):
    pass

def null_scan(host=None, port=0):
    pass

def fin_scan(host=None, port=0):
    pass

def xmas_scan(host=None, port=0):
    pass

def scan(scan_type=ScanType.CONNECT, host=None, port=0):
    if host is None or (port < MIN_PORT or port > MAX_PORT):
        # TODO throw exception on ports?
        LOGGER.warn("Invalid host or port passed for scan.")
        return
    ip = resolve_hostname(host)
    return

def valid_ip(ip=None):
    if ip is None:
        return False
    try:
        if ':' in ip:
            # handle IPv6
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        elif '.' in ip:
            # handle IPv4
            socket.inet_pton(socket.AF_INET, ip)
            return True
        else:
            LOGGER.warn("Unrecognized IP - invalid")
    except socket.error:
        pass # TODO log?

    return False

if __name__ == '__main__':
    print('testing')
    sys.exit(0)
