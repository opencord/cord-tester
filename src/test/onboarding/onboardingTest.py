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
import os,sys
import keystoneclient.v2_0.client as ksclient
import keystoneclient.apiclient.exceptions
import neutronclient.v2_0.client as nclient
import neutronclient.common.exceptions
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
import neutronclient.v2_0.client as neutronclient
from nose.tools import assert_equal
from CordTestUtils import get_mac, log_test
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl
from OnboardingServiceUtils import OnboardingServiceUtils
from SSHTestAgent import SSHTestAgent
from CordTestUtils import running_on_pod
import requests
import time
import json

class onboarding_exchange():
    ONOS_INSTANCES = 3
    V_INF1 = 'veth0'
    device_id = 'of:' + get_mac()
    TEST_IP = '8.8.8.8'
    HOST = "10.1.0.1"
    USER = "vagrant"
    PASS = "vagrant"
    head_node = os.getenv('HEAD_NODE', 'prod')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    test_path = os.path.dirname(os.path.realpath(__file__))
    on_pod = running_on_pod()

    @classmethod
    def setUpClass(cls):
        OnboardingServiceUtils.setUp()

    @classmethod
    def tearDownClass(cls):
        OnboardingServiceUtils.tearDown()

    def cliEnter(self, controller = None):
        retries = 0
        while retries < 30:
            self.cli = OnosCliDriver(controller = controller, connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

    def onos_shutdown(self, controller = None):
        status = True
        self.cliEnter(controller = controller)
        try:
            self.cli.shutdown(timeout = 10)
        except:
            log.info('Graceful shutdown of ONOS failed for controller: %s' %controller)
            status = False

        self.cliExit()
        return status

    def test_exampleservice_health(self):
        """
        Algo:
        1. Login to compute node VM
        2. Get all exampleservice
        3. Ping to all exampleservice
        4. Verifying Ping success
        """
        status = OnboardingServiceUtils.health_check()
        assert_equal(status, True)

    def test_exampleservice_for_login(self):
        if self.on_pod is False:
            return
        exampleservices = OnboardingServiceUtils.get_exampleservices()
        exampleservice_access_status = map(lambda exampleservice: exampleservice.check_access(), exampleservices)
        status = filter(lambda st: st == False, exampleservice_access_status)
        assert_equal(len(status), 0)

    def test_exampleservice_for_default_route_through_testclient(self):
       if self.on_pod is False:
           return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_exampleservice_for_service_access_through_testclient(self):
        if self.on_pod is False:
            return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "lxc exec testclient -- ping -c 3 8.8.8.8"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal( status, True)

    def test_exampleservice_for_apache_service(self):
        pass

    def test_exampleservice_for_tenant_message(self):
        pass

    def test_exampleservice_for_service_message(self):
        pass

    def test_exampleservice_using__curl(self):
        pass
