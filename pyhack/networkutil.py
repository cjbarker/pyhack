#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""networkutil provides various utility around network programming validation and object factories.
"""

from __future__ import print_function

import socket
from scapy.all import IP

import pyhack.log as log

# Globals
MIN_PORT = 1
MAX_PORT = 65535

LOGGER = log.get_logger("networkutil")

def valid_port(port=0):
    """Validates if given network port number is valid for use.

    :param: port number to validate
    :type: int
    :return: denotes true if port falls within valid range check
    :rtype: bool
    """
    return port >= MIN_PORT and port <= MAX_PORT

def valid_ip(ip_addr=None):
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
        LOGGER.error("Unable to validate IP addr due to %s", str(err))
    return False

def resolve_hostname(host=None):
    """Leverages socket to ip_addr address for a given hostname.
    If already ip_addr address resolve ignored.

    :param: hostname to resolve
    :type: str
    :return: ip_addr address of resolved hostname
    :rtype: str
    :raise: socket.gaierror if fails to resolve host
    """
    if valid_ip(host):
        return host
    try:
        ip_addr = socket.gethostbyname(host)
        return ip_addr
    except socket.gaierror, err:
        LOGGER.warn("Unable to resolve hostname: %s due to error: %s", host, str(err))
        raise err

# src_ip, dst_ip, sport, dport
# Protocol and flags denotes for TCP
def __create_ip(tcp_udp="tcp", flags=None, **kwargs):
    # TODO src IP and port not required
    if 'dport' in kwargs and not valid_port(kwargs.get("dport")):
        # TODO raise error?
        pass
    if 'sport' in kwargs and not valid_port(kwargs.get("sport")):
        # TODO raise error?
        pass
    if 'src_ip' in kwargs and not valid_ip(kwargs.get("src_ip")):
        # TODO raise error?
        pass
    if 'dst_ip' in kwargs and not valid_ip(kwargs.get("dst_ip")):
        # TODO raise error?
        pass
    if tcp_udp != 'tcp' and tcp_udp != 'udp':
        # TODO raise error
        pass
    if flags and tcp_udp == 'tcp':
        # TODO raise error cannot pass flags for UDP
        pass
    # TODO create/wrap UDP or TCP?
    s_ip = IP(src=kwargs.get("src_ip"), dst=kwargs.get("dst_ip"))
    return s_ip
