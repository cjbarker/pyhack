#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest
import random
import socket
import time
import threading

import pyhack.log as log
import pyhack.networkutil as net

# Globals
LOGGER = log.get_logger("test_networkutil")

class TestNetworkUtil(unittest.TestCase):

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

if __name__ == "__main__":
    unittest.main()
