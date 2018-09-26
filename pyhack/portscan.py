#!/usr/bin/env python

# -*- coding: utf-8 -*-

"""portscan provides functionality to apply various network port scanning techniques to a given IP address and
port."""

from __future__ import print_function
from enum import Enum

import logging
import sys
import socket

# Globals
MIN_PORT = 1
MAX_PORT = 65535
LOGGER = logging.getLogger()

class ScanType(Enum):
    ALL = 1
    PING = 2
    HALF_OPEN = 3
    CONNECT = 4
    NULL = 5
    FIN = 6
    XMAS = 7

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
    # TODO convert host to IP
    '''
    nmScan = nmapPortScanner()
    nmScan.scan(host, port)
    state = nmScan[host]['tcp'][int(port)]['state']
    print("[*] " + host + " tcp/" + port + " " + state)
    '''
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
            print('None of these ' + ip)
    except socket.error:
        pass # TODO log?

    return False

if __name__ == '__main__':
    print('testing')
    sys.exit(0)
