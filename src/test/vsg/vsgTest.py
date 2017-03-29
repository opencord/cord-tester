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
import time
import os
import sys
import json
from nose.tools import *
from CordTestUtils import *
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from SSHTestAgent import SSHTestAgent
from CordLogger import CordLogger
from VSGAccess import VSGAccess
from CordTestUtils import log_test as log

log.setLevel('INFO')

class vsg_exchange(CordLogger):
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
    olt_conf_file = os.path.join(test_path, '..', 'setup/olt_config.json')
    restApiXos =  None
    subscriber_account_num_base = 200

    @classmethod
    def setUpCordApi(cls):
        our_path = os.path.dirname(os.path.realpath(__file__))
        cord_api_path = os.path.join(our_path, '..', 'cord-api')
        framework_path = os.path.join(cord_api_path, 'Framework')
        utils_path = os.path.join(framework_path, 'utils')
        data_path = os.path.join(cord_api_path, 'Tests', 'data')
        subscriber_cfg = os.path.join(data_path, 'Subscriber.json')
        volt_tenant_cfg = os.path.join(data_path, 'VoltTenant.json')

        with open(subscriber_cfg) as f:
            subscriber_data = json.load(f)
            subscriber_info = subscriber_data['SubscriberInfo']
            account_num = cls.subscriber_account_num_base
            for subscriber in subscriber_info:
                subscriber['identity']['account_num'] = str(account_num)
                account_num += 1
            cls.subscriber_info = subscriber_info

        with open(volt_tenant_cfg) as f:
            volt_tenant_data = json.load(f)
            volt_subscriber_info = volt_tenant_data['voltSubscriberInfo']
            assert_equal(len(volt_subscriber_info), len(cls.subscriber_info))
            account_num = cls.subscriber_account_num_base
            for volt_subscriber in volt_subscriber_info:
                volt_subscriber['account_num'] = account_num
                account_num += 1
            cls.volt_subscriber_info = volt_subscriber_info

        sys.path.append(utils_path)
        sys.path.append(framework_path)
        from restApi import restApi
        restApiXos = restApi()
        restApiXos.controllerIP = cls.HEAD_NODE
        cls.restApiXos = restApiXos

    @classmethod
    def setUpClass(cls):
        cls.controllers = get_controllers()
        cls.controller = cls.controllers[0]
        cls.cli = None
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
        VSGAccess.setUp()
        cls.setUpCordApi()

    @classmethod
    def tearDownClass(cls):
        VSGAccess.tearDown()

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

    def test_vsg_health(self):
        status = VSGAccess.health_check()
        assert_equal(status, True)

    def test_vsg_for_vcpe(self):
        vsgs = VSGAccess.get_vsgs()
        compute_nodes = VSGAccess.get_compute_nodes()
        assert_not_equal(len(vsgs), 0)
        assert_not_equal(len(compute_nodes), 0)

    def test_vsg_for_login(self):
        vsgs = VSGAccess.get_vsgs()
        vsg_access_status = map(lambda vsg: vsg.check_access(), vsgs)
        status = filter(lambda st: st == False, vsg_access_status)
        assert_equal(len(status), 0)

    def test_vsg_for_default_route_through_testclient(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_vsg_for_external_connectivity_through_testclient(self):
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "lxc exec testclient -- ping -c 3 8.8.8.8"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal( status, True)

    def test_vsg_for_external_connectivity(self):
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        host = '8.8.8.8'
        self.success = False
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp echo requests to external network 8.8.8.8')
        st, _ = getstatusoutput('ping -c 3 8.8.8.8')
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def test_vsg_for_external_connectivity_to_google(self):
        host = 'www.google.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def test_vsg_for_external_connectivity_to_invalid_host(self):
        host = 'www.goglee.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to non existent host %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

    def test_vsg_for_external_connectivity_with_ttl_1(self):
        host = '8.8.8.8'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to host %s with ttl 1' %host)
        st, _ = getstatusoutput('ping -c 1 -t 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

    def test_vsg_for_external_connectivity_with_wan_interface_toggle_in_vcpe(self):
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = VSGAccess.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the wan interface and check again
        st = VSGAccess.vcpe_wan_down(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = VSGAccess.vcpe_wan_up(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

    def test_vsg_for_external_connectivity_with_lan_interface_toggle_in_vcpe(self):
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = VSGAccess.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the lan interface and check again
        st = VSGAccess.vcpe_lan_down(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = VSGAccess.vcpe_lan_up(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

    def test_vsg_firewall_with_deny_destination_ip(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_with_rule_add_and_delete_dest_ip(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_verifying_reachability_for_non_blocked_dest_ip(self, vcpe=None):
        host1 = '8.8.8.8'
        host2 = '204.79.197.203'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        assert_equal(st, False)
        try:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host1))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_appending_rules_with_deny_dest_ip(self, vcpe=None):
        host1 = '8.8.8.8'
        host2 = '204.79.197.203'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host1))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st, False)
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host2))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,True)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_removing_one_rule_denying_dest_ip(self, vcpe=None):
        host1 = '8.8.8.8'
        host2 = '204.79.197.203'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host1))
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host2))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe,host2))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_changing_rule_id_deny_dest_ip(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -j ACCEPT 2'.format(vcpe))
            st,output = vsg.run_cmd('sudo docker exec {} iptables -A FORWARD 2 -d {} -j DROP '.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_changing_deny_rule_to_accept_dest_ip(self, vcpe=None):
        host1 = '8.8.8.8'
        host2 = '204.79.197.203'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -A FORWARD -d {} -j ACCEPT 1'.format(vcpe,host))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_denying_destination_network(self, vcpe=None):
        network = '206.190.36.44/28'
        host1 = '204.79.197.46'
        host2 = '204.79.197.51'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,network))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_denying_destination_network_subnet_modification(self, vcpe=None):
        network1 = '206.190.36.44/28'
        network2 = '206.190.36.44/26'
        host1 = '204.79.197.46'
        host2 = '204.79.197.51'
        host2 = '204.79.197.63'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,network1))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st,False)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -A FORWARD -d {} -j DROP'.format(vcpe,network2))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
            assert_equal(st, True)
            st, _ = getstatusoutput('ping -c 1 {}'.format(host3))
            assert_equal(st, False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_with_deny_source_ip(self, vcpe=None):
        host = '8.8.8.8'
        source_ip = self.vcpe_dhcp
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe,source_ip))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_rule_with_add_and_delete_deny_source_ip(self, vcpe=None):
        host = '8.8.8.8'
        source_ip = self.vcpe_dhcp
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe,source_ip))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe,source_ip))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_requests_type(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
        finally:
            vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))

    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_reply_type(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format('8.8.8.8'))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_requests_type(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 1 -p icmp --icmp-type echo-request -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 1 -p icmp --icmp-type echo-request -j ACCEPT'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_reply_type(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, out1 = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 1 -p icmp --icmp-type echo-reply -j DROP'.format(vcpe))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 1 -p icmp --icmp-type echo-reply -j ACCEPT'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_for_deny_icmp_protocol(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_rule_deny_icmp_protocol_and_destination_ip(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe,host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe))
            st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st,False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_firewall_flushing_all_configured_rules(self, vcpe=None):
        host = '8.8.8.8'
        if not vcpe:
                vcpe = self.vcpe_container
        vsg = VSGAccess.get_vcpe_vsg(vcpe)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        assert_equal(st, False)
        try:
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st,output = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
        finally:
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -X'.format(vcpe))
            st, _ = vsg.run_cmd('sudo docker exec {} iptables -F'.format(vcpe))

    def test_vsg_xos_subscriber(self):
        subscriber_info = self.subscriber_info[0]
        volt_subscriber_info = self.volt_subscriber_info[0]
        result = self.restApiXos.ApiPost('TENANT_SUBSCRIBER', subscriber_info)
        assert_equal(result, True)
        result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        assert_not_equal(result, None)
        subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
        assert_not_equal(subId, '0')
        log.info('Subscriber ID for account num %d = %s' %(volt_subscriber_info['account_num'], subId))
        volt_tenant = volt_subscriber_info['voltTenant']
        #update the subscriber id in the tenant info before making the rest
        volt_tenant['subscriber'] = subId
        result = self.restApiXos.ApiPost('TENANT_VOLT', volt_tenant)
        assert_equal(result, True)

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
