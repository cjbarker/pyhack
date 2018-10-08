#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""networkutil provides various utility around network programming validation and object factories.
"""

from __future__ import print_function

import socket
from scapy.all import *
from scapy.all import IP, UDP, TCP

import pyhack.log as log

# Globals
MIN_PORT = 1
MAX_PORT = 65535

# Globals
LOGGER = log.get_logger("networkutil")

TCP_FLAGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

class ValidationError(Exception):
    """Custom validation exception for error handling in creating scapy packets"""
    def __init__(self, message, errors):
        super(ValidationError, self).__init__(message)
        self.errors = errors

def valid_flags(flags=None):
    """Validates TCP packet flags

    :param: flags to validate
    :type: str
    :return: denotes true if flags are valid TCP falgs
    :rtype: bool
    """
    if flags is None or flags == "":
        return True
    flags = flags.strip().upper()
    try:
        convert_flags(flags)
        return True
    except KeyError:
        return False

def convert_flags(flags=None):
    """Converts string of TCP flags of single chars to list of 3 letter value
    describing the flag.

    :param: flags to convert to list
    :type: str
    :return: sequence of TCP flags code converted to 3 character string prefix
    :rtype: list 
    """
    if flags is None or flags == "":
        return None
    flags = flags.strip().upper()
    return [TCP_FLAGS[x] for x in flags]

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

def create_packets(is_tcp=True, flags=None, **kwargs):
    """Creates IP and associated TCP or UDP corresponding packets via Scapy

    :param: is_tcp denotes if TCP otherwise UDP packet will be created
    :type: bool
    :param: flags TCP flags to enabel in packet, ex: 'AFS'
    :type: str
    :return: scapy packets
    :rtype: pkt
    :raise: ValidationError if method parameter validation fails
    """
    errors = {}
    if flags and not valid_flags(flags):
        errors["tcp_flags"] = "Invalid TCP flag(s): " + flags
    if 'dport' in kwargs and not valid_port(kwargs.get("dport")):
        errors["dport"] = "Invalid destination port " + str(kwargs.get("dport"))
    if 'sport' in kwargs and not valid_port(kwargs.get("sport")):
        errors["sport"] = "Invalid source port " + str(kwargs.get("sport"))
    if 'src' in kwargs and not valid_ip(kwargs.get("src")):
        errors["src"] = "Invalid source IP address " + kwargs.get("src")
    if 'dst' in kwargs and not valid_ip(kwargs.get("dst")):
        errors["dst"] = "Invalid destination IP address " + kwargs.get("dst")
    if 'dst' not in kwargs:
        errors["dst"] = "Destination IP address required"
    if flags and not is_tcp:
        errors["udp_flags"] = "Invalid flags cannot be passed for UDP message"
    if is_tcp and 'dport' not in kwargs:
        errors["tcp_dport"] = "Destination port required for TCP packet"
    if errors:
        raise ValidationError("Invalid IP creation", errors)

    # create scapy packet(s)
    ip_packet = IP(dst=kwargs.get("dst"))
    if 'src' in kwargs:
        ip_packet.src = kwargs.get("src")
    LOGGER.debug("TCP setting is " + flags)
    if is_tcp:
        tcp_packet = TCP(dport=int(kwargs.get("dport")))
        if 'sport' in kwargs:
            tcp_packet.sport = int(kwargs.get("sport"))
        tcp_packet.flags = flags
        packets = ip_packet/tcp_packet
    else:
        udp_packet = UDP(dport=int(kwargs.get("dport")))
        if 'sport' in kwargs:
            udp_packet.sport = int(kwargs.get("sport"))
        packets = ip_packet/udp_packet

    LOGGER.debug(packets.show())
    return packets
