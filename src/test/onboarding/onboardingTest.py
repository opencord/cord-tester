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
from CordLogger import CordLogger
from CordTestUtils import log_test as log
import requests
import time
import json

class onboarding_exchange(CordLogger):
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
	log.info('list of all exampleservices are %s'%exampleservices)
        """exampleservice_access_status = map(lambda exampleservice: exampleservice.check_access(), exampleservices)
        status = filter(lambda st: st == False, exampleservice_access_status)
        assert_equal(len(status), 0)"""

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

    def get_exampleservice_vm_public_ip(self,vm='mysite_exampleservice'):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "nova list --all-tenants|grep {}|cut -d '|' -f 2".format(vm)
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        return public_ip

    def test_exampleservice_operational_status_from_testclient(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        #Wait for ExampleService VM to come up
        cmd = "nova list --all-tenants|grep 'exampleservice.*ACTIVE'"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get ID of VM
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get mgmt IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 172\.27\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, mgmt_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get name of compute node
        cmd = "nova service-list|grep nova-compute|cut -d '|' -f 3"
        status, compute_node = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Wait for Apache to come up inside VM
        cmd = "ssh -o ProxyCommand='ssh -W %h:%p -l ubuntu {}' ubuntu@{} 'ls /var/run/apache2/apache2.pid'".fromat(compute_node,mgmt_ip)
        #Make sure testclient has default route to vSG
        cmd = "lxc exec testclient -- route | grep default | grep eth0.222.111"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        cmd = 'lxc exec testclient -- apt-get install -y curl'
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Test connectivity to ExampleService from test client
        cmd = 'lxc exec testclient -- curl -s http://{}'.format(public_ip)
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_subscribers_operational_status_for_exampleservice_from_cord_tester(self):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(cmd)
            assert_equal(st, True)
        finally:
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)

    def test_subscriber_access_status_for_exampleservice_after_subscriber_interface_toggle(self,vcpe_intf=None):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        #Get public IP of VM
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(cmd)
            assert_equal(st, True)
            st,_ = getstatusoutput('ifconfig {} down'.format(vcpe_intf))
            assert_equal(st, True)
            st,_ = getstatusoutput(cmd)
            assert_equal(st, True)
        finally:
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)

    def test_subscriber_access_status_for_exampleservice_after_service_restart(self, vcpe_intf=None):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            #restarting example service VM
            cmd = 'nova reset-state {}'.format(nova_id)
            status, _ = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            time.sleep(10)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
        finally:
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)

    def test_subcriber_access_status_for_exampleservice_after_service_stop(self, vcpe_intf=None):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            #restarting example service VM
            cmd = 'nova stop {}'.format(nova_id)
            status, _ = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            time.sleep(1)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, False)
            cmd = 'nova start {}'.format(nova_id)
            status, _ = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            time.sleep(1)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
        finally:
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)

    def test_multiple_subcriber_access_for_same_exampleservice(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "nova list --all-tenants|grep mysite_exampleservice|cut -d '|' -f 2"
        status, nova_id = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Get public IP of VM
        cmd = 'nova interface-list {} |grep -o -m 1 10\.6\.[[:digit:]]*\.[[:digit:]]*'.format(nova_id)
        status, public_ip = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        for vcpe in self.dhcp_vcpes:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe)
            time.sleep(1)

    def test_exampleservice_after_vcpe_instance_restart(self,vcpe_intf=None,vcpe_name=None):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        public_ip = self.get_exampleservice_vm_public_ip()
        vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            #restarting example service VM
            cmd = 'sudo docker restart {}'.format(vcpe_name)
            status, _ = vsg.run_cmd(cmd)
            assert_equal(status, True)
            time.sleep(10)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
        finally:
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)

    def test_exampleservice_after_firewall_rule_added_to_drop_service_running_server_ip_in_vcpe(self):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        public_ip = self.get_exampleservice_vm_public_ip()
        vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            #restarting example service VM
            st,_ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j ACCEPT'.format(vcpe_name,public_ip))
            time.sleep(1)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, False)
        finally:
            st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,public_ip))
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
