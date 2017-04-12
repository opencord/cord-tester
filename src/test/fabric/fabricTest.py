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
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from TestManifest import TestManifest
from Fabric import FabricMAAS, Fabric
from CordTestUtils import log_test as log
import os
log.setLevel('INFO')

class fabric_exchange(unittest.TestCase):

    node_list = []
    fabric = None
    FABRIC_TEST_TIMEOUT = 30
    key_file = os.getenv('SSH_KEY_FILE', None)
    api_key = os.getenv('MAAS_API_KEY', 'UNKNOWN')

    @classmethod
    def setUpClass(cls):
        if cls.api_key == 'UNKNOWN':
            return
        maas = FabricMAAS(api_key = cls.api_key)
        cls.node_list = maas.get_node_list()
        cls.fabric = Fabric(cls.node_list, key_file = cls.key_file, verbose = False)

    @deferred(FABRIC_TEST_TIMEOUT)
    def test_fabric(self):
        """Test the connectivity between the compute nodes"""
        df = defer.Deferred()
        def verify_fabric(df):
            assert_not_equal(self.fabric, None)
            failed_nodes = []
            failed_nodes = self.fabric.ping_neighbors()
            if failed_nodes:
                log.info('Failed nodes: %s' %failed_nodes)
                for node, neighbor, _ in failed_nodes:
                    log.info('Ping from node %s to neighbor %s Failed' %(node, neighbor))
            assert_equal(len(failed_nodes), 0)
            df.callback(0)
        reactor.callLater(0, verify_fabric, df)
        return df
