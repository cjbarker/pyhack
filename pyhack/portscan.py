#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import nmap
import sys
import socket

# Globals
MIN_PORT=1
MAX_PORT=65535
RE_IPV4=""
RE_IPV6=""

def nmap_scan(host=None, port=0):
    if host == None or port == 0:
        return
    #nmScan = nmapPortScanner()

def valid_ip(ip=None):
    if ip == None:
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
    except socket.error, e:
        # TODO log?
        pass

    return False

if __name__ == '__main__':
    print('testing')
    sys.exit(0)
