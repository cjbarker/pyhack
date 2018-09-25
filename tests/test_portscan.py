#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import pyhack.portscan as pscan

class TestPortScan(unittest.TestCase):

    def setUp(self):
        pass

    def test_valid_ip(self):
        # IPv4
        self.assertFalse(pscan.valid_ip(None))
        self.assertFalse(pscan.valid_ip('30.168.1.255.1'))
        self.assertTrue(pscan.valid_ip('127.0.0.1'))
        self.assertTrue(pscan.valid_ip('192.168.0.1'))
        self.assertTrue(pscan.valid_ip('255.255.255.255'))
        self.assertTrue(pscan.valid_ip('0.0.0.0'))
        self.assertTrue(pscan.valid_ip('1.1.1.01'))
        # IPv6
        self.assertTrue(pscan.valid_ip('1:2:3:4:5:6:7:8'))
        self.assertTrue(pscan.valid_ip('2001:db8:3:4::192.0.2.33'))
        self.assertTrue(pscan.valid_ip('::255.255.255.255'))
        self.assertTrue(pscan.valid_ip('::ffff:255.255.255.255'))

if __name__ == "__main__":
    unittest.main()
