import unittest
import time
import os
import json
from nose.tools import *
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl
from scapy.all import *

log.setLevel('INFO')

class routes_exchange(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cli = OnosCliDriver(connect = True)

    @classmethod
    def tearDownClass(cls):
        cls.cli.disconnect()

    def test_route_cli(self):
        routes = json.loads(self.cli.routes(jsonFormat = True))
        log.info('Routes: %s' %routes)

    def test_devices_cli(self):
        devices = json.loads(self.cli.devices(jsonFormat = True))
        available_devices = filter(lambda d: d['available'], devices)
        device_ids = [ d['id'] for d in devices ]
        log.info('Available Devices: %s' %devices)
        log.info('Device IDS: %s' %device_ids)

    def test_flows_cli(self):
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        log.info('Flows: %s' %flows)
