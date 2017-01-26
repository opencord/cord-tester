#copyright 2016-present Ciena Corporation
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
from scapy.all import *
from OnosCtrl import OnosCtrl, get_mac
from OltConfig import OltConfig
from socket import socket
from OnosFlowCtrl import OnosFlowCtrl
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_onos_shutdown
from portmaps import g_subscriber_port_map
from scapy.all import *
import time, monotonic
from OnosLog import OnosLog
from CordLogger import CordLogger
from os import environ as env
import os
import json
import random
import collections
import paramiko
from paramiko import SSHClient
log.setLevel('INFO')

class vsg_exchange(CordLogger):
    ONOS_INSTANCES = 3
    V_INF1 = 'veth0'
    device_id = 'of:' + get_mac()
    testcaseLoggers = ("")
    TEST_IP = '8.8.8.8'
    HOST = "10.1.0.1"
    USER = "vagrant"
    PASS = "vagrant"


    def setUp(self):
        if self._testMethodName not in self.testcaseLoggers:
            super(vsg_exchange, self).setUp()

    def tearDown(self):
        if self._testMethodName not in self.testcaseLoggers:
            super(vsg_exchange, self).tearDown()

    def get_controller(self):
        controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
        controller = controller.split(',')[0]
        return controller

    @classmethod
    def get_controllers(cls):
        controllers = os.getenv('ONOS_CONTROLLER_IP') or ''
        return controllers.split(',')

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

    def log_set(self, level = None, app = 'org.onosproject', controllers = None):
        CordLogger.logSet(level = level, app = app, controllers = controllers, forced = True)

    def get_nova_credentials_v2():
        credential = {}
        credential['version'] = '2'
        credential['username'] = env['OS_USERNAME']
        credential['api_key'] = env['OS_PASSWORD']
        credential['auth_url'] = env['OS_AUTH_URL']
        credential['project_id'] = env['OS_TENANT_NAME']
        return credential

    def get_vsg_ip(vm_id):
        credentials = get_nova_credentials_v2()
        nova_client = Client(**credentials)
        result = nova_client.servers.list()
        for server in result:
            print server;

    def health_check(self):
        cmd = "nova list --all-tenants|grep mysite_vsg|cut -d '|' -f 2"
        status, nova_id = commands.getstatusoutput(cmd)
        cmd = "nova interface-list {{ nova_id }}|grep -o -m 1 '172\.27\.[[:digit:]]*\.[[:digit:]]*'"
        status, ip = commands.getstatusoutput(cmd)
        cmd = "ping -c1 {0}".format(ip)
        status =  os.system(cmd)
        return status

    def ping_ip(remote, ip):
        results = []
        cmd = "ping -c1 {0}".format(ip)
        result = remote.execute(cmd, verbose=False)
        return results

    def vsg_vm_ssh_check(vsg_ip):
        cmd = "nc -z -v "+str(vsg_ip)+" 22"
        status =  os.system(cmd)
        return status

    def get_vcpe(self):
        cmd = "nova list --all-tenants|grep mysite_vsg|cut -d '|' -f 2"
        status, node_id = commands.getstatusoutput(cmd)

    def connect_ssh(vsg_ip, private_key_file=None, user='ubuntu'):
        key = ssh.RSAKey.from_private_key_file(private_key_file)
        client = ssh.SSHClient()
        client.set_missing_host_key_policy(ssh.WarningPolicy())
        client.connect(ip, username=user, pkey=key, timeout=5)
        return client

    def test_vsg_vm(self):
        status = self.health_check()
        assert_equal( status, False)

    def test_vsg_for_default_route_to_vsg_vm(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect( self.HOST, username = self.USER, password=self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        stdin, stdout, stderr = client.exec_command(cmd)
        status = stdout.channel.recv_exit_status()
        assert_equal( status, False)

    def test_vsg_vm_for_vcpe(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect( self.HOST, username = self.USER, password=self.PASS)
        cmd = "nova service-list|grep nova-compute|cut -d '|' -f 3"
        stdin, stdout, stderr = client.exec_command(cmd)
        cmd = "nova list --all-tenants | grep mysite_vsg|cut -d '|' -f 7 | cut -d '=' -f 2 | cut -d ';' -f 1"
        status, ip = commands.getstatusoutput(cmd)
        #cmd = "ssh -o ProxyCommand="ssh -W %h:%p -l ubuntu {0}" ubuntu@{1} "sudo docker ps|grep vcpe"".format(compute_node_name, ip)
        status = stdout.channel.recv_exit_status()
        assert_equal( status, False)

    def test_vsg_for_external_connectivity(self):
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect( self.HOST, username = self.USER, password=self.PASS)
        cmd = "lxc exec testclient -- ping -c 3 8.8.8.8"
        stdin, stdout, stderr = client.exec_command(cmd)
        status = stdout.channel.recv_exit_status()
        assert_equal( status, False)

    def test_vsg_cord_subscriber_creation(self):
        pass

    def test_vsg_for_dhcp_client(self):
        pass

    def test_vsg_for_snat(self):
        pass

    def test_vsg_for_dns_service(self):
        pass

    def test_vsg_dnsmasq(self):
        pass

    def test_vsg_with_external_parental_control_family_shield_for_filter(self):
        pass

    def test_vsg_with_external_parental_control_with_answerx(self):
        pass

    def test_vsg_for_subscriber_upstream_bandwidth(self):
        pass

    def test_vsg_for_subscriber_downstream_bandwidth(self):
        pass

    def test_vsg_for_diagnostic_run_of_traceroute(self):
        pass

    def test_vsg_for_diagnostic_run_of_tcpdump(self):
        pass

    def test_vsg_for_iptable_rules(self):
        pass

    def test_vsg_for_iptables_with_neutron(self):
        pass

