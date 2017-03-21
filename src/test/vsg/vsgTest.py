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
from CordTestUtils import *
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from socket import socket
from OnosFlowCtrl import OnosFlowCtrl
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_onos_shutdown
from SSHTestAgent import SSHTestAgent
from portmaps import g_subscriber_port_map
from scapy.all import *
import time, monotonic
from OnosLog import OnosLog
from CordLogger import CordLogger
import os
import shutil
import json
import random
import collections
import paramiko
import re
from paramiko import SSHClient
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as nova_client
log.setLevel('INFO')

class vsg_exchange(CordLogger):
    ONOS_INSTANCES = 3
    V_INF1 = 'veth0'
    device_id = 'of:' + get_mac()
    TEST_IP = '8.8.8.8'
    HOST = "10.1.0.1"
    USER = "vagrant"
    PASS = "vagrant"
    head_node = os.environ['HEAD_NODE']
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    test_path = os.path.dirname(os.path.realpath(__file__))
    olt_conf_file = os.path.join(test_path, '..', 'setup/olt_config.json')
    ip_addr_pattern = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')

    @classmethod
    def setUpClass(cls):
        cls.controllers = get_controllers()
        cls.controller = cls.controllers[0]
        cls.cli = None
        cls.interface_map = {}
        cls.vcpe_map = {}
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.vcpes = cls.olt.get_vcpes()
        cls.vcpes_dhcp = cls.olt.get_vcpes_by_type('dhcp')
        vcpe_dhcp = None
        vcpe_dhcp_stag = None
        vcpe_container = None
        #cache the first dhcp vcpe in the class for quick testing
        if cls.vcpes_dhcp:
            vcpe_container = 'vcpe-{}-{}'.format(cls.vcpes_dhcp[0]['s_tag'], cls.vcpes_dhcp[0]['c_tag'])
            vcpe_dhcp = 'vcpe0.{}.{}'.format(cls.vcpes_dhcp[0]['s_tag'], cls.vcpes_dhcp[0]['c_tag'])
            vcpe_dhcp_stag = 'vcpe0.{}'.format(cls.vcpes_dhcp[0]['s_tag'])
        cls.vcpe_container = vcpe_container
        cls.vcpe_dhcp = vcpe_dhcp
        cls.vcpe_dhcp_stag = vcpe_dhcp_stag
        try:
            shutil.copy('/etc/resolv.conf', '/etc/resolv.conf.orig')
        except:
            pass

    @classmethod
    def tearDownClass(cls):
        try:
            shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
        except:
            pass

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

    def log_set(self, level = None, app = 'org.onosproject'):
        CordLogger.logSet(level = level, app = app, controllers = self.controllers, forced = True)

    def get_nova_credentials_v2(self):
        credential = {}
        credential['username'] = os.environ['OS_USERNAME']
        credential['api_key'] = os.environ['OS_PASSWORD']
        credential['auth_url'] = os.environ['OS_AUTH_URL']
        credential['project_id'] = os.environ['OS_TENANT_NAME']
        return credential

    def get_compute_nodes(self):
        credentials = self.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        return nvclient.hypervisors.list()

    def get_vsgs(self, active = True):
        credentials = self.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        vsgs = nvclient.servers.list(search_opts = {'all_tenants': 1})
        if active is True:
            return filter(lambda vsg: vsg.status == 'ACTIVE', vsgs)
        return vsgs

    def get_vsg_ip(self, vm_name):
        vsgs = self.get_vsgs()
        vms = filter(lambda vsg: vsg.name == vm_name, vsgs)
        if vms:
            vm = vms[0]
            if vm.networks.has_key('management'):
                ips = vm.networks['management']
                if len(ips) > 0:
                    return ips[0]
        return None

    def get_compute_node(self, vsg):
        return vsg._info['OS-EXT-SRV-ATTR:hypervisor_hostname']

    def run_cmd_compute(self, compute, cmd, timeout = 5):
        ssh_agent = SSHTestAgent(compute)
        st, output = ssh_agent.run_cmd(cmd, timeout = timeout)
        if st == True and output:
            output = output.strip()
        else:
            output = None

        return st, output

    def run_cmd_vsg(self, compute, vsg_ip, cmd, timeout = 5, mgmt = 'eth0'):
        last_gw = self.open_compute(mgmt)
        ssh_agent = SSHTestAgent(compute)
        ssh_cmd = 'ssh {} {}'.format(vsg_ip, cmd)
        st, output = ssh_agent.run_cmd(ssh_cmd, timeout = timeout)
        if st == True and output:
            output = output.strip()
        else:
            output = None
        self.close_compute(last_gw, mgmt)
        return st, output

    #ping the vsg through the compute node.
    #the ssh key is already used by SSHTestAgent in cord-tester
    def get_vsg_health(self, vsg):
        compute_node = self.get_compute_node(vsg)
        vsg_ip = self.get_vsg_ip(vsg.name)
        if vsg_ip is None:
            return False
        cmd = 'ping -c 1 {}'.format(vsg_ip)
        st, _ = self.run_cmd_compute(compute_node, cmd)
        return st

    #returns 0 if all active vsgs are reachable through the compute node
    def health_check(self):
        vsgs = self.get_vsgs()
        vsg_status = []
        for vsg in vsgs:
            vsg_status.append(self.get_vsg_health(vsg))
        unreachable = filter(lambda st: st == False, vsg_status)
        return len(unreachable) == 0

    #find the vsg hosting the vcpe service
    def get_vcpe_vsg(self, vcpe):
        if vcpe in self.vcpe_map:
            return self.vcpe_map[vcpe]['vsg']
        vsgs = self.get_vsgs()
        for vsg in vsgs:
            vsg_ip = self.get_vsg_ip(vsg.name)
            compute_node = self.get_compute_node(vsg)
            cmd = 'sudo docker exec {} ls 2>/dev/null'.format(vcpe)
            st, _ = self.run_cmd_vsg(compute_node, vsg_ip, cmd, timeout = 30)
            if st == True:
                return vsg
        return None

    def save_vcpe_config(self, vsg, vcpe):
        if vcpe not in self.vcpe_map:
            cmd_gw = "sudo docker exec %s ip route show | grep default | head -1 | awk '{print $3}'" %(vcpe)
            vsg_ip = self.get_vsg_ip(vsg.name)
            if vsg_ip is None:
                return False
            compute_node = self.get_compute_node(vsg)
            st, output = self.run_cmd_vsg(compute_node, vsg_ip, cmd_gw, timeout = 30)
            if st == False or not output:
                return False
            gw = output
            cmd_wan = "sudo docker exec %s ip addr show eth0 |grep inet |head -1 | tr -s ' ' | awk '{print $2}' | awk '{print $1}'" %(vcpe)
            cmd_lan = "sudo docker exec %s ip addr show eth1 |grep inet |head -1 | tr -s ' ' | awk '{print $2}' | awk '{print $1}'" %(vcpe)
            st, output = self.run_cmd_vsg(compute_node, vsg_ip, cmd_wan, timeout = 30)
            ip_wan = '0.0.0.0/24'
            ip_lan = '0.0.0.0/24'
            if st and output:
                if self.ip_addr_pattern.match(output):
                    ip_wan = output

            st, output = self.run_cmd_vsg(compute_node, vsg_ip, cmd_lan, timeout = 30)
            if st and output:
                if self.ip_addr_pattern.match(output):
                    ip_lan = output

            self.vcpe_map[vcpe] = { 'vsg': vsg, 'vsg_ip': vsg_ip, 'gw': gw, 'wan': ip_wan, 'lan': ip_lan }

        return True

    def restore_vcpe_config(self, vcpe, gw = True, wan = False, lan = False):
        if vcpe in self.vcpe_map:
            vsg = self.vcpe_map[vcpe]['vsg']
            vsg_ip = self.vcpe_map[vcpe]['vsg_ip']
            compute_node = self.get_compute_node(vsg)
            cmds = []
            if gw is True:
                #restore default gw
                gw = self.vcpe_map[vcpe]['gw']
                cmds.append('sudo docker exec {} ip link set eth0 up'.format(vcpe))
                cmds.append('sudo docker exec {} route add default gw {} dev eth0'.format(vcpe, gw))
            if wan is True:
                ip_wan = self.vcpe_map[vcpe]['wan']
                cmds.append('sudo docker exec {} ip addr set {} dev eth0'.format(vcpe, ip_wan))
            if lan is True:
                ip_lan = self.vcpe_map[vcpe]['lan']
                cmds.append('sudo docker exec {} ip addr set {} dev eth1'.format(vcpe, ip_lan))
            ret_status = True
            for cmd in cmds:
                st, _ = self.run_cmd_vsg(compute_node, vsg_ip, cmd, timeout = 30)
                if st == False:
                    ret_status = False
            return ret_status
        return False

    def get_vcpe_gw(self, vcpe):
        if vcpe in self.vcpe_map:
            return self.vcpe_map[vcpe]['gw']
        return None

    def get_vcpe_wan(self, vcpe):
        if vcpe in self.vcpe_map:
            return self.vcpe_map[vcpe]['wan']
        return None

    def get_vcpe_lan(self, vcpe):
        if vcpe in self.vcpe_map:
            return self.vcpe_map[vcpe]['lan']
        return None

    def vcpe_wan_up(self, vcpe, vsg = None):
        if vsg is None:
            vsg = self.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        return self.restore_vcpe_config(vcpe)

    def vcpe_lan_up(self, vcpe, vsg = None):
        if vsg is None:
            vsg = self.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        if vcpe in self.vcpe_map:
            vsg_ip = self.vcpe_map[vcpe]['vsg_ip']
        else:
            vsg_ip = self.get_vsg_ip(vsg.name)
        compute_node = self.get_compute_node(vsg)
        cmd = 'sudo docker exec {} ip link set eth1 up'.format(vcpe)
        st, _ = self.run_cmd_vsg(compute_node, vsg_ip, cmd, timeout = 30)
        return st

    #we cannot access compute node if the vcpe port gets dhcp as default would be through fabric
    def vcpe_port_down(self, vcpe, port, vsg = None):
        if vsg is None:
            vsg = self.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        if not self.save_vcpe_config(vsg, vcpe):
            return False
        vsg_ip = self.get_vsg_ip(vsg.name)
        compute_node = self.get_compute_node(vsg)
        cmd = 'sudo docker exec {} ip link set {} down'.format(vcpe, port)
        st, _ = self.run_cmd_vsg(compute_node, vsg_ip, cmd, timeout = 30)
        if st is False:
            self.restore_vcpe_config(vcpe)
            return False
        return st

    def vcpe_wan_down(self, vcpe, vsg = None):
        return self.vcpe_port_down(vcpe, 'eth0', vsg = vsg)

    def vcpe_lan_down(self, vcpe, vsg = None):
        return self.vcpe_port_down(vcpe, 'eth1', vsg = vsg)

    #use SSHTestAgent to talk to the vsg through the compute node like in get_vsg_health
    # def connect_ssh(vsg_ip, private_key_file=None, user='ubuntu'):
    #     key = ssh.RSAKey.from_private_key_file(private_key_file)
    #     client = ssh.SSHClient()
    #     client.set_missing_host_key_policy(ssh.WarningPolicy())
    #     client.connect(ip, username=user, pkey=key, timeout=5)
    #     return client

    def test_vsg_vm(self):
        status = self.health_check()
        assert_equal( status, True)

    def test_vsg_for_default_route_to_vsg_vm(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_vsg_vm_for_vcpe(self):
        vsgs = self.get_vsgs()
        compute_nodes = self.get_compute_nodes()
        assert_not_equal(len(vsgs), 0)
        assert_not_equal(len(compute_nodes), 0)

    #TODO: use cord-test container itself to dhclient on vcpe interfaces
    #using the info from OltConfig().get_vcpes()
    #deleting default through eth0, fetching ip through dhclient on vcpe,
    #and testing for dhcp ip on vcpe0 and default route on vcpe0 before pinging 8.8.8.8
    def test_vsg_for_external_connectivity(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "lxc exec testclient -- ping -c 3 8.8.8.8"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal( status, True)

    def check_vsg_access(self, vsg):
        compute_node = self.get_compute_node(vsg)
        vsg_ip = self.get_vsg_ip(vsg.name)
        if vsg_ip is None:
            return False
        ssh_agent = SSHTestAgent(compute_node)
        st, _ = ssh_agent.run_cmd('ls', timeout=10)
        if st == False:
            return st
        st, _ = ssh_agent.run_cmd('ssh {} ls'.format(vsg_ip), timeout=30)
        return st

    def test_vsg_vm_for_login_to_vsg(self):
        vsgs = self.get_vsgs()
        vsg_access_status = map(self.check_vsg_access, vsgs)
        status = filter(lambda st: st == False, vsg_access_status)
        assert_equal(len(status), 0)

    def save_interface_config(self, intf):
        if intf not in self.interface_map:
            ip = get_ip(intf)
            if ip is None:
                ip = '0.0.0.0'
            default_gw, default_gw_device = get_default_gw()
            if default_gw_device != intf:
                default_gw = '0.0.0.0'
            self.interface_map[intf] = { 'ip' : ip, 'gw': default_gw }
            #bounce the interface to remove default gw
            cmds = ['ifconfig {} 0 down'.format(intf),
                    'ifconfig {} 0 up'.format(intf)
                    ]
            for cmd in cmds:
                os.system(cmd)

    #open up access to compute node
    def open_compute(self, intf = 'eth0'):
        if intf in self.interface_map:
            gw = self.interface_map[intf]['gw']
            ip = self.interface_map[intf]['ip']
            if gw != '0.0.0.0':
                current_gw, _ = get_default_gw()
                cmds = [ 'route del default gw {}'.format(current_gw),
                         'ifconfig {} {} up'.format(intf, ip),
                         'route add default gw {}'.format(gw) ]
                for cmd in cmds:
                    os.system(cmd)
                shutil.copy('/etc/resolv.conf', '/etc/resolv.conf.lastdhcp')
                shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
                return current_gw

        return None

    def close_compute(self, restore_gw, intf = 'eth0'):
        if restore_gw:
            cmds = [ 'route del default gw 0.0.0.0',
                     'route add default gw {}'.format(restore_gw),
                     'cp /etc/resolv.conf.lastdhcp /etc/resolv.conf',
                     'rm -f /etc/resolv.conf.lastdhcp'
                     ]
            for cmd in cmds:
                os.system(cmd)

    def restore_interface_config(self, intf, vcpe = None):
        if intf in self.interface_map:
            ip = self.interface_map[intf]['ip']
            gw = self.interface_map[intf]['gw']
            del self.interface_map[intf]
            cmds = []
            if vcpe is not None:
                shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
                #bounce the vcpes to clear default gw
                cmds.append('ifconfig {} 0 down'.format(vcpe))
                cmds.append('ifconfig {} 0 up'.format(vcpe))
            cmds.append('ifconfig {} {} up'.format(intf, ip))
            if gw and gw != '0.0.0.0':
                cmds.append('route add default gw {} dev {}'.format(gw, intf))
            for cmd in cmds:
                os.system(cmd)

    def vcpe_get_dhcp(self, vcpe, mgmt = 'eth0'):
        self.save_interface_config(mgmt)
        getstatusoutput('pkill -9 dhclient')
        st, output = getstatusoutput('dhclient -q {}'.format(vcpe))
        getstatusoutput('pkill -9 dhclient')
        vcpe_ip = get_ip(vcpe)
        if vcpe_ip is None:
            self.restore_interface_config(mgmt)
            return None
        if output:
            #workaround for docker container apparmor that prevents moving dhclient resolv.conf
            start = output.find('/etc/resolv.conf')
            if start >= 0:
                end = output.find("'", start)
                dns_file = output[start:end]
                if os.access(dns_file, os.F_OK):
                    shutil.copy(dns_file, '/etc/resolv.conf')

        default_gw, default_gw_device = get_default_gw()
        if default_gw and default_gw_device == vcpe:
            return vcpe_ip
        self.restore_interface_config(mgmt, vcpe = vcpe)
        return None

    #these need to first get dhcp through dhclient on vcpe interfaces (using OltConfig get_vcpes())
    def test_vsg_external_connectivity_with_sending_icmp_echo_requests(self):
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        host = '8.8.8.8'
        self.success = False
        assert_not_equal(vcpe, None)
        vcpe_ip = self.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp echo requests to external network 8.8.8.8')
        st, _ = getstatusoutput('ping -c 3 8.8.8.8')
        self.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def test_vsg_external_connectivity_sending_icmp_ping_on_different_interface(self):
        host = '8.8.8.8'
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Recieved icmp echo reply which is not expected')
                self.success = True
            sniff(count=1, timeout=5,
                 lfilter = lambda p: IP in p and p[ICMP].type == 0,
                 prn = recv_cb, iface = 'vcpe0.222.112')
        t = threading.Thread(target = mac_recv_task)
        t.start()
        L3 = IP(dst = host)
        pkt = L3/ICMP()
        log.info('Sending icmp echo requests to external network')
        send(pkt, count=3, iface = 'vcpe0.222.112')
        t.join()
        assert_equal(self.success, False)

    def test_vsg_external_connectivity_pinging_with_single_tag_negative_scenario(self):
        host = '8.8.8.8'
        self.success = False
        assert_not_equal(self.vcpe_dhcp_stag, None)
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Recieved icmp echo reply which is not expected')
                self.success = True
            sniff(count=1, timeout=5,
                  lfilter = lambda p: IP in p and p[ICMP].type == 0,
                  prn = recv_cb, iface = self.vcpe_dhcp_stag)
        t = threading.Thread(target = mac_recv_task)
        t.start()
        L3 = IP(dst = host)
        pkt = L3/ICMP()
        log.info('Sending icmp echo requests to external network')
        send(pkt, count=3, iface = self.vcpe_dhcp_stag)
        t.join()
        assert_equal(self.success, False)

    def test_vsg_external_connectivity_pinging_to_google(self):
        host = 'www.google.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = self.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        self.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def test_vsg_external_connectivity_pinging_to_non_existing_website(self):
        host = 'www.goglee.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = self.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to non existent host %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        self.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

    def test_vsg_external_connectivity_ping_to_google_with_ttl_1(self):
        host = '8.8.8.8'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = self.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to host %s with ttl 1' %host)
        st, _ = getstatusoutput('ping -c 1 -t 1 {}'.format(host))
        self.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

    def test_vsg_for_external_connectivity_with_wan_interface_down_and_making_up_in_vcpe_container(self):
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = self.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the wan interface and check again
        st = self.vcpe_wan_down(vcpe)
        if st is False:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = self.vcpe_wan_up(vcpe)
        if st is False:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

    def test_vsg_for_external_connectivity_with_lan_interface_down_and_up_in_vcpe_container(self):
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = self.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the lan interface and check again
        st = self.vcpe_lan_down(vcpe)
        if st is False:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = self.vcpe_lan_up(vcpe)
        if st is False:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            self.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

    def test_vsg_for_ping_from_vsg_to_external_network(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Ensure VM created properly
	3.Verify login to VM success
	4.Do ping to external network from vSG VM
	5.Verify that ping gets success
	6.Verify ping success flows added in OvS
	"""
    def test_vsg_for_ping_from_vcpe_to_external_network(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container inside VM
	3.Verify both VM and Container created properly
        4.Verify login to vCPE container success
        5.Do ping to external network from vCPE container
        6.Verify that ping gets success
        7.Verify ping success flows added in OvS
        """

    def test_vsg_for_dns_service(self):
	"""
	Algo:
	1. Create a test client  in Prod VM
	2. Create a vCPE container in vSG VM inside compute Node
	3. Ensure vSG VM and vCPE container created properly
	4. Enable dns service in vCPE ( if not by default )
	5. Send ping request from test client to valid domain  address say, 'www.google'com
	6. Verify that dns should resolve ping should success
	7. Now  send ping request to invalid domain address say 'www.invalidaddress'.com'
	8. Verify that dns resolve should fail and hence ping
        """
    def test_vsg_for_10_subscribers_for_same_service(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Create 10 vCPE containers for 10 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
	4.From each of the subscriber, with same s-tag and different c-tag, send a ping to valid external public IP
	5.Verify that ping success for all 10 subscribers
	"""
    def test_vsg_for_10_subscribers_for_same_service_ping_invalid_ip(self):
        """
        Algo:
        1.Create a vSG VM in compute Node
	2.Create 10 vCPE containers for 10 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From each of the subscriber, with same s-tag and different c-tag, send a ping to invalid IP
        5.Verify that ping fails for all 10 subscribers
        """
    def test_vsg_for_10_subscribers_for_same_service_ping_valid_and_invalid_ip(self):
        """
        Algo:
        1.Create a vSG VM in VM
	2.Create 10 vCPE containers for 10 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From first 5 subscribers, with same s-tag and different c-tag, send a ping to valid IP
        5.Verify that ping success for all 5 subscribers
        6.From next 5 subscribers, with same s-tag and different c-tag, send a ping to invalid IP
        7.Verify that ping fails for all 5 subscribers
        """
    def test_vsg_for_100_subscribers_for_same_service(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Create 100 vCPE containers for 100 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
	4.From each of the subscriber, with same s-tag and different c-tag, send a ping to valid external public IP
	5.Verify that ping success for all 100 subscribers
	"""
    def test_vsg_for_100_subscribers_for_same_service_ping_invalid_ip(self):
        """
        Algo:
        1.Create a vSG VM in compute Node
	2.Create 10 vCPE containers for 100 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From each of the subscriber, with same s-tag and different c-tag, send a ping to invalid IP
        5.Verify that ping fails for all 100 subscribers
        """
    def test_vsg_for_100_subscribers_for_same_service_ping_valid_and_invalid_ip(self):
        """
        Algo:
        1.Create a vSG VM in VM
	2.Create 10 vCPE containers for 100 subscribers, in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From first 5 subscribers, with same s-tag and different c-tag, send a ping to valid IP
        5.Verify that ping success for all 5 subscribers
        6.From next 5 subscribers, with same s-tag and different c-tag, send a ping to invalid IP
        7.Verify that ping fails for all 5 subscribers
        """
    def test_vsg_for_packet_received_with_invalid_ip_fields(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
	4.From subscriber, send a ping packet with invalid ip fields
	5.Verify that vSG drops the packet
	6.Verify ping fails
	"""
    def test_vsg_for_packet_received_with_invalid_mac_fields(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send a ping packet with invalid mac fields
        5.Verify that vSG drops the packet
        6.Verify ping fails
        """
    def test_vsg_for_vlan_id_mismatch_in_stag(self):
        """
        Algo:
        1.Create a vSG VM in compute Node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.Send a ping request to external valid IP from subscriber, with incorrect vlan id in  s-tag and valid c-tag
        5.Verify that ping fails as the packet drops at VM entry
        6.Repeat step 4 with correct s-tag
	7.Verify that ping success
        """
    def test_vsg_for_vlan_id_mismatch_in_ctag(self):
        """
        Algo:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.Send a ping request to external valid IP from subscriber, with valid s-tag and incorrect vlan id in c-tag
        5.Verify that ping fails as the packet drops at vCPE container entry
        6.Repeat step 4 with valid s-tag and c-tag
        7.Verify that ping success
        """
    def test_vsg_for_matching_and_mismatching_vlan_id_in_stag(self):
        """
        Algo:
        1.Create two vSG VMs in compute node
	2.Create a vCPE container in each vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber one, send ping request with valid s and c tags
        5.From subscriber two, send ping request with vlan id mismatch in s-tag and valid c tags
        6.Verify that ping success for only subscriber one and fails for two.
        """
    def test_vsg_for_matching_and_mismatching_vlan_id_in_ctag(self):
        """
        Algo:
        1.Create a vSG VM in compute node
	2.Create two vCPE containers in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber one, send ping request with valid s and c tags
        5.From subscriber two, send ping request with valid s-tag and vlan id mismatch in c-tag
        6.Verify that ping success for only subscriber one and fails for two
        """
    def test_vsg_for_out_of_range_vlanid_in_ctag(self):
        """
        Algo:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid stag and vlan id in c-tag is an out of range value ( like 0,4097 )
        4.Verify that ping fails as the ping packets drops at vCPE container entry
        """
    def test_vsg_for_out_of_range_vlanid_in_stag(self):
        """
        Algo:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        2.From subscriber, send ping request with vlan id in s-tag is an out of range value ( like 0,4097 ), with valid c-tag
        4.Verify that ping fails as the ping packets drops at vSG VM entry
        """
    def test_vsg_without_creating_vcpe_instance(self):
	"""
	Algo:
	1.Create a vSG VM in compute Node
	2.Ensure vSG VM created properly
	3.Do not create vCPE container inside vSG VM
	4.From a subscriber, send ping to external valid IP
	5.Verify that ping fails as the ping packet drops at vSG VM entry itself.
	"""
    def test_vsg_for_remove_vcpe_instance(self):
	"""
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid s-tag and c-tag
        5.Verify that ping success
	6.Verify ping success flows in OvS switch in compute node
	7.Now remove the vCPE container in vSG VM
	8.Ensure that the container removed properly
	9.Repeat step 4
	10.Verify that now, ping fails
        """
    def test_vsg_for_restart_vcpe_instance(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid s-tag and c-tag
        5.Verify that ping success
        6.Verify ping success flows in OvS switch in compute node
        7.Now restart the vCPE container in vSG VM
        8.Ensure that the container came up after restart
        9.Repeat step 4
        10.Verify that now,ping gets success and flows added in OvS
        """
    def test_vsg_for_restart_vsg_vm(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid s-tag and c-tag
        5.Verify that ping success
        6.Verify ping success flows in OvS switch in compute node
        7.Now restart the vSG VM
        8.Ensure that the vSG comes up properly after restart
	9.Verify that vCPE container comes up after vSG restart
        10.Repeat step 4
        11.Verify that now,ping gets success and flows added in OvS
        """
    def test_vsg_for_pause_vcpe_instance(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid s-tag and c-tag
        5.Verify that ping success
        6.Verify ping success flows in OvS switch in compute node
        7.Now pause vCPE container in vSG VM for a while
        8.Ensure that the container state is pause
        9.Repeat step 4
        10.Verify that now,ping fails now and verify flows in OvS
	11.Now  resume the container
	12.Now repeat step 4 again
	13.Verify that now, ping gets success
	14.Verify ping success flows in OvS
        """
    def test_vsg_for_extract_all_compute_stats_from_all_vcpe_containers(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Create 10 vCPE containers in VM
	3.Ensure vSG VM and vCPE containers created properly
	4.Login to all vCPE containers
	4.Get all compute stats from all vCPE containers
	5.Verify the stats # verification method need to add
	"""
    def test_vsg_for_extract_dns_stats_from_all_vcpe_containers(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create 10 vCPE containers in VM
        3.Ensure vSG VM and vCPE containers created properly
	4.From  10 subscribers, send ping to valid and invalid dns hosts
        5.Verify dns resolves and ping success for valid dns hosts
	6.Verify ping fails for invalid dns hosts
        7.Verify dns host name resolve flows in OvS
	8.Login to all 10 vCPE containers
	9.Extract all dns stats
	10.Verify dns stats for queries sent, queries received for dns host resolve success and failed scenarios
        """
    def test_vsg_for_subscriber_access_two_vsg_services(self):
	"""
	# Intention is to verify if subscriber can reach internet via two vSG VMs
	Algo:
	1.Create two vSG VMs for two services in compute node
	2.Create one vCPE container in each VM for one subscriber
	3.Ensure VMs and containers created properly
	4.From subscriber end, send ping to public IP with stag corresponds to vSG-1 VM and ctag
	5.Verify ping gets success
	6.Verify ping success flows in OvS
	7.Now repeat step 4 with stag corresponds to vSG-2 VM
	8.Verify that ping again success
	9.Verify ping success flows in OvS
	"""
    def test_vsg_for_subscriber_access_service2_if_service1_goes_down(self):
	"""
	# Intention is to verify if subscriber can reach internet via vSG2 if vSG1 goes down
        Algo:
        1.Create two vSG VMs for two services in compute node
        2.Create one vCPE container in each VM for one subscriber
        3.Ensure VMs and containers created properly
        4.From subscriber end, send ping to public IP with stag corresponds to vSG-1 VM and ctag
        5.Verify ping gets success
        6.Verify ping success flows in OvS
	7.Down the vSG-1 VM
        8.Now repeat step 4
	9.Verify that ping fails as vSG-1 is down
        10.Repeat step 4 with stag corresponding to vSG-2
        9.Verify ping success and flows added in OvS
        """
    def test_vsg_for_subscriber_access_service2_if_service1_goes_restart(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 restarts
        Algo:
        1.Create two vSG VMs for two services in compute node
        2.Create one vCPE container in each VM for one subscriber
        3.Ensure VMs and containers created properly
        4.From subscriber end, send ping to public IP with stag corresponds to vSG-1 VM and ctag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now restart vSG-1 VM
        8.Now repeat step 4 while vSG-1 VM restarts
        9.Verify that ping fails as vSG-1 is restarting
        10.Repeat step 4 with stag corresponding to vSG-2 while vSG-1 VM restarts
        11.Verify ping success and flows added in OvS
        """
    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_goes_down(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 goes down
        Algo:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now stop vCPE-1 container
        8.Now repeat step 4
        9.Verify that ping fails as vCPE-1 container is down
        10.Repeat step 4 with ctag corresponding to vCPE-2 container
        11.Verify ping success and flows added in OvS
        """
    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_restart(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 restarts
        Algo:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now restart vCPE-1 container
        8.Now repeat step 4 while vCPE-1 restarts
        9.Verify that ping fails as vCPE-1 container is restarts
        10.Repeat step 4 with ctag corresponding to vCPE-2 container while vCPE-1 restarts
        11..Verify ping success and flows added in OvS
        """
    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_pause(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 paused
        Algo:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now pause vCPE-1 container
        8.Now repeat step 4 while vCPE-1 in pause state
        9.Verify that ping fails as vCPE-1 container in pause state
        10.Repeat step 4 with ctag corresponding to vCPE-2 container while vCPE-1 in pause state
        11.Verify ping success and flows added in OvS
        """
    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_removed(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 removed
        Algo:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vCPE-1 container
        8.Now repeat step 4
        9.Verify that ping fails as vCPE-1 container removed
        10.Repeat step 4 with ctag corresponding to vCPE-2 container
        11.Verify ping success and flows added in OvS
        """
    def test_vsg_for_vcpe_instance_removed_and_added_again(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber end, send ping to public IP
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vCPE container in vSG VM
        8.Now repeat step 4
        9.Verify that ping fails as vCPE container removed
	10.Create the vCPE container again for the same subscriber
	11.Ensure that vCPE created now
        12.Now repeat step 4
        13.Verify ping success and flows added in OvS
        """
    def test_vsg_for_vsg_vm_removed_and_added_again(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber end, send ping to public IP
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vSG VM
        8.Now repeat step 4
        9.Verify that ping fails as vSG VM not exists
        10.Create the vSG VM and vCPE  container in VM again
        11.Ensure that vSG and vCPE created
        12.Now repeat step 4
        13.Verify ping success and flows added in OvS
        """

    #Test vSG - Subscriber Configuration
    def test_vsg_for_configuring_new_subscriber_in_vcpe(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
	4.Configure a subscriber in XOS and assign a service id
	5.Set the admin privileges to the subscriber
	6.Verify subscriber configuration is success
	"""
    def test_vsg_for_adding_subscriber_devices_in_vcpe(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
	5.Verify subscriber successfully configured in vCPE
	6.Now add devices( Mac addresses ) under the subscriber admin group
	7.Verify all devices ( Macs ) added successfully
	"""
    def test_vsg_for_removing_subscriber_devices_in_vcpe(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
	8.Now remove All the added devices in XOS
	9.Verify all the devices removed
        """
    def test_vsg_for_modify_subscriber_devices_in_vcpe(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a user in XOS and assign a service id
        5.Verify subscriber successfully configured in vCPE.
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
        8.Now remove few devices in XOS
        9.Verify devices removed successfully
	10.Now add few additional devices in XOS  under the same subscriber admin group
	11.Verify newly added devices successfully added
        """
    def test_vsg_for_vcpe_login_fails_with_incorrect_subscriber_credentials(self):
	"""
	Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
	8.Login vCPE with credentials with which subscriber configured
	9.Verify subscriber successfully logged in
	10.Logout and login again with incorrect credentials ( either user name or password )
	11.Verify login attempt to vCPE fails wtih incorrect credentials
	"""
    def test_vsg_for_subscriber_configuration_in_vcpe_retain_after_vcpe_restart(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS  and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
        8.Restart vCPE ( locate backup config path while restart )
        9.Verify subscriber details in vCPE after restart should be same as before the restart
        """
    def test_vsg_for_create_multiple_vcpe_instances_and_configure_subscriber_in_each_instance(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create 2 vCPE containers in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS for each vCPE instance and assign a service id
        5.Verify subscribers successfully configured
	6.Now login vCPE-2 with subscriber-1 credentials
	7.Verify login fails
	8.Now login vCPE-1 with subscriber-2 credentials
	9.Verify login fails
	10.Now login vCPE-1 with subscriber-1 and vCPE-2 with  subscriber-2 credentials
	11.Verify that both the subscribers able to login to their respective vCPE containers
	"""
    def test_vsg_for_same_subscriber_can_be_configured_for_multiple_services(self):
        """
        Algo:
        1.Create 2 vSG VMs in compute node
        2.Create a vCPE container in each vSG VM
        3.Ensure VMs and containers created properly
        4.Configure same subscriber in XOS for each vCPE instance and assign a service id
        5.Verify subscriber successfully configured
        6.Now login vCPE-1 with subscriber credentials
        7.Verify login success
        8.Now login vCPE-2 with the same subscriber credentials
        9.Verify login success
        """

    #Test Example Service
    def test_vsg_for_subcriber_avail_example_service_running_in_apache_server(self):
	"""
	Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in each vSG VM
        3.Ensure VM and container created properly
        4.Configure a subscriber in XOS for the vCPE instance and assign a service id
	5.On-board an example service into cord pod
	6.Create a VM in compute node and run the example service ( Apache server )
	7.Configure the example service with service specific and subscriber specific messages
	8.Verify example service on-boarded successfully
	9.Verify example service running in VM
	10.Run a curl command from subscriber to reach example service
	11.Verify subscriber can successfully reach example service via vSG
	12.Verify that service specific and subscriber specific messages
	"""
    def test_vsg_for_subcriber_avail_example_service_running_in_apache_server_after_service_restart(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in each vSG VM
        3.Ensure VM and container created properly
        4.Configure a subscriber in XOS for the vCPE instance and assign a service id
        5.On-board an example service into cord pod
        6.Create a VM in compute node and run the example service ( Apache server )
        7.Configure the example service with service specific and subscriber specific messages
        8.Verify example service on-boarded successfully
        9.Verify example service running in VM
        10.Run a curl command from subscriber to reach example service
        11.Verify subscriber can successfully reach example service via vSG
        12.Verify that service specific and subscriber specific messages
	13.Restart example service running in VM
	14.Repeat step 10
	15.Verify the same results as mentioned in steps 11, 12
        """

    #vCPE Firewall Functionality
    def test_vsg_firewall_for_creating_acl_rule_based_on_source_ip(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic from a source IP
        5.Bound the acl rule to WAN interface of  vCPE
        6.Verify configuration in vCPE is success
        8.Verify flows added in OvS
        """
    def test_vsg_firewall_for_creating_acl_rule_based_on_destination_ip(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic to a destination ip
        5.Bound the acl rule to WAN interface of  vCPE
        6.Verify configuration in vCPE is success
        8.Verify flows added in OvS
        """
    def test_vsg_firewall_for_acl_deny_rule_based_on_source_ip_traffic(self):
	"""
	Algo:
	1.Create a vSG VM in compute node
	2.Create vCPE container in the VM
	3.Ensure vSG VM and vCPE container created properly
	4.Configure ac acl rule in vCPE to deny IP traffic from a source IP
	5.Bound the acl rule to WAN interface of  vCPE
	6.From subscriber, send ping to the denied IP address
	7.Verify that ping fails as vCPE denies ping response
	8.Verify flows added in OvS
	"""
    def test_vsg_firewall_for_acl_deny_rule_based_on_destination_ip_traffic(self):
        """
        Algo:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic to a destination IP
        5.Bound the acl rule to WAN interface of  vCPE
        6.From subscriber, send ping to the denied IP address
        7.Verify that ping fails as vCPE drops the ping request at WAN interface
        8.Verify flows added in OvS
        """

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
