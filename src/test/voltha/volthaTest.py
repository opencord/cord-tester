import os
import sys
import unittest
from nose.tools import *
from CordTestConfig import setup_module
from CordTestUtils import log_test
from VolthaCtrl import VolthaCtrl

class voltha_exchange(unittest.TestCase):

    OLT_TYPE = 'tibit_olt'
    OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_HOST = 'localhost'
    VOLTHA_REST_PORT = 8881
    voltha = None

    @classmethod
    def setUpClass(cls):
        cls.voltha = VolthaCtrl(cls.VOLTHA_HOST, rest_port = cls.VOLTHA_REST_PORT)

    def test_olt_enable(self):
        log_test.info('Enabling OLT type %s, MAC %s' %(self.OLT_TYPE, self.OLT_MAC))
        status = self.voltha.enable_device(self.OLT_TYPE, self.OLT_MAC)
        assert_equal(status, True)
