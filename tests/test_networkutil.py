#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest
import random
import socket
import time
import threading
from scapy.all import *

import pyhack.log as log
import pyhack.networkutil as net

# Globals
LOGGER = log.get_logger("test_networkutil")

class TestNetworkUtil(unittest.TestCase):

    def test_valid_mac(self):
        self.assertFalse(net.valid_mac(None))
        self.assertFalse(net.valid_mac("   "))
        self.assertFalse(net.valid_mac(" hello  "))
        self.assertTrue(net.valid_mac("01:02:03:04:ab:cd"))
        self.assertTrue(net.valid_mac("    01:02:03:04:ab:cd "))
        self.assertTrue(net.valid_mac("01-02-03-04-ab-cd"))
        self.assertTrue(net.valid_mac("01.02.03.04.ab.cd"))
        self.assertTrue(net.valid_mac("0102-0304-abcd"))
        self.assertTrue(net.valid_mac("01020304abcd"))

    def test_valid_flags(self):
        # Good flags
        flags = ""
        for key, value in net.TCP_FLAGS.iteritems():
            self.assertTrue(net.valid_flags(str(key)))
            flags += str(key)
        self.assertTrue(net.valid_flags(flags))
        self.assertTrue(net.valid_flags("   "))
        # Bad flags
        self.assertFalse(net.valid_flags("zoo"))
        self.assertFalse(net.valid_flags("HaPpY"))

    def test_convert_flags(self):
        # Good flags
        try:
            flags = net.convert_flags("SAPU")
            self.assertEqual(len(flags), 4)
            print(flags)
        except KeyError, ex:
            self.fail(str(ex))
        # bad flags
        try:
            flags = net.convert_flags("SAPUZ")
            self.fail("Should not be able to convert invalid flags")
        except KeyError, ex:
            pass

    def test_valid_ip(self):
        # IPv4
        self.assertFalse(net.valid_ip(None))
        self.assertFalse(net.valid_ip('30.168.1.255.1'))
        self.assertTrue(net.valid_ip('127.0.0.1'))
        self.assertTrue(net.valid_ip('192.168.0.1'))
        self.assertTrue(net.valid_ip('255.255.255.255'))
        self.assertTrue(net.valid_ip('0.0.0.0'))
        #self.assertTrue(net.valid_ip('1.1.1.01'))
        # IPv6
        self.assertTrue(net.valid_ip('1:2:3:4:5:6:7:8'))
        self.assertTrue(net.valid_ip('2001:db8:3:4::192.0.2.33'))
        self.assertTrue(net.valid_ip('::255.255.255.255'))
        self.assertTrue(net.valid_ip('::ffff:255.255.255.255'))

    def test_resolve_hostname(self):
        host = 'google.com'
        try:
            ip = net.resolve_hostname(host)
            self.assertIsNotNone(host)
            ip2 = net.resolve_hostname(ip)
            self.assertIsNotNone(ip2)
            self.assertEqual(ip, ip2)
        except Exception, ex:
            self.fail(str(ex))
        # test fails
        try:
            host = 'google'
            ip = net.resolve_hostname(host)
            self.fail("Should not be able to resolve " + host)
        except:
            pass

    def test_valid_port(self):
        self.assertTrue(net.valid_port(net.MIN_PORT))
        self.assertTrue(net.valid_port(net.MAX_PORT))
        self.assertFalse(net.valid_port(net.MIN_PORT-1))
        self.assertFalse(net.valid_port(net.MAX_PORT+1))
        self.assertFalse(net.valid_port(-1234))
        self.assertFalse(net.valid_port(None))

    def test_create_packet(self):
        # bad packets
        try:
            # dest ip, dest port required
            net.create_packet(True, "AF")
            self.fail("Invalid packet - should not be able to create")
        except net.ValidationError, ex:
            self.assertTrue('dst' in ex.errors)
            self.assertTrue('tcp_dport' in ex.errors)
        try:
            # invalid protocol and flags
            net.create_packet(False, "ZOO")
            self.fail("Invalid packet - should not be able to create")
        except net.ValidationError, ex:
            self.assertTrue('udp_flags' in ex.errors)
            self.assertTrue('tcp_flags' in ex.errors)
            self.assertTrue('dst' in ex.errors)
        try:
            # invalid IPs and Ports
            net.create_packet(True, "A", dport=90000, sport=-230, dst="as..dk...", src="0981.1091.111.1") 
            self.fail("Invalid packet - should not be able to create")
        except net.ValidationError, ex:
            self.assertTrue('dport' in ex.errors)
            self.assertTrue('sport' in ex.errors)
            self.assertTrue('dst' in ex.errors)
            self.assertTrue('src' in ex.errors)

        # good packets
        try:
            packet = net.create_packet(True, "FA", dport=80, dst="198.1.1.101")
            output = packet.summary()
            self.assertTrue("FA" in output)
        except net.ValidationError, ex:
            self.fail(ex.message)
        try:
            mac = "ff:ff:ff:ff:ff:ff"
            packet = net.create_packet(True, "FA", dport=80, dst="198.1.1.101", src_mac=mac)
            self.assertEqual(mac, packet[Ether].src)
        except net.ValidationError, ex:
            self.fail(ex.message)

if __name__ == "__main__":
    unittest.main()
