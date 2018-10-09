#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""networkutil provides various utility around network programming validation and object factories.
"""

from __future__ import print_function

import socket
import re
from enum import Enum

from scapy.all import *
from scapy.all import Ether, IP, UDP, TCP, ICMP

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
"""TCP packet flags

    F, FIN - Finish/finalize last packet from sender

    S, SYN - Synchronize sequence numbers

    R, RST - Reset connection

    P, PSH - Push function

    A, ACK - Acknowledgement

    U, URG - Urgent pointer field

    E, ECE - ECN-Echo indicates SYN flag set or cleared depending on if ECN capable peer

    C, CWR - Congestion Window Reduced
"""

class PacketProto(Enum):
    """Packet protocol defined for use in packet creation within scapy

        TCP - Indicates TCP packet layer

        UDP - Indicates UDP packet layer

        ICMP - Indicates ICMP packet layer
    """
    TCP = 1
    UDP = 2
    ICMP = 3

class ValidationError(Exception):
    """Custom validation exception for error handling in creating scapy packets"""
    def __init__(self, message, errors):
        super(ValidationError, self).__init__(message)
        self.errors = errors

def valid_mac(mac=None):
    """Validates Ethernet MAC Address

    :param: mac address to validate
    :type: str
    :return: denotes true if MAC proper format else flase
    :rtype: bool
    """
    if mac is None or mac.strip() == "":
        return False
    mac = mac.strip()
    return re.match("^([0-9A-Fa-f]{2}[:.-]?){5}([0-9A-Fa-f]{2})$", mac)

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

def create_packet(packet_proto=PacketProto.TCP, **kwargs):
    """Creates network packet of  IP and associated TCP or UDP corresponding packets via Scapy

    :param: packet_proto denotes IP packet layer (protocol) to create, ex: TCP, UDP, ICMP
    :type: PacketProto
    :param: flags TCP flags to enabel in packet, ex: 'AFS'
    :type: str
    :param: kwargs dictionary for packet creation
        src = IP address of source
        sport = IP source port
        dst = IP address of destination
        dport = IP destination port
        src_mac = Ethernet MAC address of source
    :rtype: dict
    :return: scapy packet
    :rtype: pkt
    :raise: ValidationError if method parameter validation fails
    """
    errors = {}
    if 'flags' in kwargs and not valid_flags(kwargs.get('flags')):
        errors["tcp_flags"] = "Invalid TCP flag(s): " + kwargs.get('flags')
    if 'flags' in kwargs and packet_proto != PacketProto.TCP:
        errors["flags"] = "Invalid flags cannot be passed non TCP packet"
    if 'dport' in kwargs and not valid_port(kwargs.get("dport")):
        errors["dport"] = "Invalid destination port " + str(kwargs.get("dport"))
    if 'sport' in kwargs and not valid_port(kwargs.get("sport")):
        errors["sport"] = "Invalid source port " + str(kwargs.get("sport"))
    if 'src' in kwargs and not valid_ip(kwargs.get("src")):
        errors["src"] = "Invalid source IP address " + kwargs.get("src")
    if 'dst' in kwargs and not valid_ip(kwargs.get("dst")):
        errors["dst"] = "Invalid destination IP address " + kwargs.get("dst")
    if 'src_mac' in kwargs and not valid_mac(kwargs.get("src_mac")):
        errors["src_mac"] = "Invalid source MAC address " + kwargs.get("src_mac")
    if 'dst' not in kwargs:
        errors["dst"] = "Destination IP address required"
    if packet_proto == PacketProto.TCP and 'dport' not in kwargs:
        errors["tcp_dport"] = "Destination port required for TCP packet"
    if errors:
        raise ValidationError("Invalid IP creation", errors)

    # create scapy packet
    # pylint: disable=invalid-name
    ip = IP(dst=kwargs.get("dst"))
    if 'src' in kwargs:
        ip.src = kwargs.get("src")
        LOGGER.debug("Set Src IP " + ip.src)

    if packet_proto == PacketProto.TCP:
        tcp = TCP(dport=int(kwargs.get("dport")))
        if 'sport' in kwargs:
            tcp .sport = int(kwargs.get("sport"))
        tcp.flags = kwargs.get("flags")
        LOGGER.debug("Set TCP Flags " + str(tcp.flags))
        packet = ip/tcp
    elif packet_proto == PacketProto.UDP:
        udp = UDP(dport=int(kwargs.get("dport")))
        LOGGER.debug("Set UDP Dest Port " + str(udp.dport))
        if 'sport' in kwargs:
            udp.sport = int(kwargs.get("sport"))
            LOGGER.debug("Set UDP Src Port " + str(udp.sport))
        packet = ip/udp
    elif packet_proto == PacketProto.ICMP:
        LOGGER.debug("Set ICMP packet")
        icmp = ICMP()
        packet = ip/icmp
    else:
        errors["packet_proto"] = "Invalid packet protocol passed (unrecognized)"
        raise ValidationError("Invalid IP creation", errors)

    if 'src_mac' in kwargs:
        ether = Ether(src=kwargs.get("src_mac"))
        LOGGER.debug("Set Ethernet MAC Addr " + ether.src)
        packet = ether/packet

    LOGGER.debug(packet.show())
    return packet
