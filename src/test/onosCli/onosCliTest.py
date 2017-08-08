
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#
# Copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import unittest
import time
import os
import json
from nose.tools import *
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl
from CordTestUtils import log_test as log

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
