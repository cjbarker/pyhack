#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import unittest
import random
import socket
import time
import threading

import pyhack.log as log
import pyhack.portscan as pscan

# Globals
LOGGER = log.get_logger("test_portscan")

class Server:
    def __init__(self, host, port, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def handle_client(self):
        # Server will just close the connection after it opens it
        LOGGER.debug("Server accepting connections...")
        self.sock.accept()
        # TODO send something
        self.sock.close()
        LOGGER.debug("Server socket closed")
        return

    def start_listening(self):
        self.sock = socket.socket()
        self.sock.settimeout(100)
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.timeout)
        client_handler = threading.Thread(target=self.handle_client)
        client_handler.start()

class Client:
    def __init__(self, host, port, timeout=1):
        self.host = host
        self.port = port
        self.timeout = timeout

    def valid_conn(self):
        try:
            self.sock = socket.socket()
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            self.sock.close()
            return True
        except:
            return False

def getPort():
    """Generate random port number that does not require root for running socket listener on.

    :return: port number between 1025 and 65535
    :rtype: int
    """
    return random.randint(1025, pscan.MAX_PORT)

class TestPortScan(unittest.TestCase):

    HOST = '127.0.0.1'
    PORT = 0

    def setUp(self):
        self.PORT = getPort()
        LOGGER.debug("Creating server " + self.HOST + " listening on port " + str(self.PORT))

        svr = Server(self.HOST, self.PORT)
        svr_thread = threading.Thread(target=svr.start_listening)
        svr_thread.daemon = True # die when main dies
        svr_thread.start()

        # test client connect
        client = Client(self.HOST, self.PORT)
        LOGGER.debug("Client connection valid: " + str(client.valid_conn()))

        # On my computer, 0.0000001 is the minimum sleep time or the
        # client might connect before server thread binds and listens
        # Other computers will differ. I wanted a low number to make tests fast
        time.sleep(0.000001)

        svr_thread.join()

    def tearDown(self):
        # TODO shutdown server
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

    def test_nmap_scan(self):
        # validate server running an connect
        client = Client(self.HOST, self.PORT)
        #print('Client able to connect ' + client.valid_conn())

if __name__ == "__main__":
    unittest.main()
