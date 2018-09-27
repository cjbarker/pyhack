#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""portscan provides functionality to apply various network port scanning
techniques to a given ip_addr address and port.
"""

from __future__ import print_function
from enum import Enum

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
    """Leverages socket to ip_addr address for a given hostname.
    If already ip_addr address resolve ignored.

    :param: hostname to resolve
    :type: str
    :return: ip_addr address of resolved hostname
    :rtype: str
    :raise: socket.gaierror if fails to resolve host
    """
    if valid_ip_addr(host):
        return host
    try:
        ip_addr = socket.gethostbyname(host)
        return ip_addr
    except socket.gaierror, err:
        LOGGER.warn("Unable to resolve hostname: %s", host)
        raise err

def valid_port(port=0):
    """Validates if given network port number is valid for use.

    :param: port number to validate
    :type: int
    :return: denotes true if port falls within valid range check
    :rtype: bool
    """
    return port >= MIN_PORT and port <= MAX_PORT

def ping_scan(host=None, port=0):
    """Applies UDP ICMP aka PING port scan and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def half_open_scan(host=None, port=0):
    """Applies TCP syn-ack aka half-open port scan and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def connect_scan(host=None, port=0):
    """Applies TCP connection (3-way handshake) port scan and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def null_scan(host=None, port=0):
    """Applies TCP NULL flag packet port scan and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def fin_scan(host=None, port=0):
    """Applies TCP FIN flag packet port scan and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def xmas_scan(host=None, port=0):
    """Applies full flag TCP packet aka XMAS tree port scan
    and outputs results to STDOUT.

    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    pass

def scan(scan_type=ScanType.CONNECT, host=None, port=0):
    """Applies appropriate port scan and outputs result to STDOUT.
    Defaults to TCP Connect scan of 3 way handshake if scan type not applied.

    :param: Type of network port scan to apply
    :type: ScanType
    :param: Hostname or IP address v4 or v6 to scan
    :type: str
    :param: Port to scan
    :type: int
    """
    if host is None or (port < MIN_PORT or port > MAX_PORT):
        LOGGER.warn("Invalid host or port passed for scan.")
        return
    ip_addr = resolve_hostname(host)
    do_all = (scan_type == ScanType.ALL)
    if do_all or scan_type == ScanType.CONNECT:
        connect_scan(host, port)
    if do_all or scan_type == ScanType.FIN:
        fin_scan(host, port)
    if do_all or scan_type == ScanType.HALF_OPEN:
        half_open_scan(host, port)
    if do_all or scan_type == ScanType.NULL:
        null_scan(host, port)
    if do_all or scan_type == ScanType.PING:
        ping_scan(host, port)
    if do_all or scan_type == ScanType.XMAS:
        xmas_scan(host, port)
    return

def valid_ip_addr(ip_addr=None):
    """Validates IP address is valid version 4 or 6. Will return False if exception raised.

    :param: IP address to validate
    :type: str
    :return: denotes whether or not valid IPv4 or v6
    :rtype: bool
    """
    if ip_addr is None:
        return False
    try:
        if ':' in ip_addr:
            # handle ip_addrv6
            socket.inet_pton(socket.AF_INET6, ip_addr)
            return True
        elif '.' in ip_addr:
            # handle ip_addrv4
            socket.inet_pton(socket.AF_INET, ip_addr)
            return True
        else:
            LOGGER.warn("Invalid and Unrecognized ip_addr, %s", ip_addr)
    except socket.error, err:
        LOGGER.error("Unable to valid IP address due to %s", err.msg)
    return False

if __name__ == '__main__':
    print('testing')
    sys.exit(0)
