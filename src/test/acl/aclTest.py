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
from scapy.all import *
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnosFlowCtrl import OnosFlowCtrl
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos
from portmaps import g_subscriber_port_map
from CordTestServer import cord_test_onos_restart
from ACL import ACLTest
from CordTestConfig import setup_module, teardown_module
import threading
import time
import os
import json
import pexpect
log.setLevel('INFO')

class acl_exchange(unittest.TestCase):

    app = ('org.onosproject.acl')
    test_path = os.path.dirname(os.path.realpath(__file__))
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '192.168.10.50'
    INGRESS_PORT = 1
    EGRESS_PORT = 2
    ingress_iface = 1
    egress_iface = 2
    MAX_PORTS = 100
    CURRENT_PORT_NUM = egress_iface
    ACL_SRC_IP = '192.168.20.3/32'
    ACL_DST_IP = '192.168.30.2/32'
    ACL_SRC_IP_RULE_2 = '192.168.40.3/32'
    ACL_DST_IP_RULE_2 = '192.168.50.2/32'
    ACL_SRC_IP_PREFIX_24 = '192.168.20.3/24'
    ACL_DST_IP_PREFIX_24 = '192.168.30.2/24'
    HOST_DST_IP = '192.168.30.0/24'
    HOST_DST_IP_RULE_2 = '192.168.50.0/24'

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map,_ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        time.sleep(3)
        log.info('port_map = %s'%cls.port_map[1] )

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the acl app'''

    def setUp(self):
        ''' Activate the acl app'''
        self.maxDiff = None ##for assert_equal compare outputs on failure
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)
        status, _ = ACLTest.remove_acl_rule()
        log.info('Start setup')
        assert_equal(status, True)

    def tearDown(self):
        '''Deactivate the acl app'''
        log.info('Tear down setup')
        self.CURRENT_PORT_NUM = 4

    def cliEnter(self):
        retries = 0
        while retries < 3:
            self.cli = OnosCliDriver(connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

    @classmethod
    def acl_hosts_add(cls, dstHostIpMac, egress_iface_count = 1,  egress_iface_num = None):
        index = 0
        if egress_iface_num is None:
            egress_iface_num = cls.egress_iface
        for ip,_ in dstHostIpMac:
            egress = cls.port_map[egress_iface_num]
            log.info('Assigning ip %s to interface %s' %(ip, egress))
            config_cmds_egress = ( 'ifconfig {} 0'.format(egress),
                                   'ifconfig {0} up'.format(egress),
                                   'ifconfig {0} {1}'.format(egress, ip),
                                   'arping -I {0} {1} -c 2'.format(egress, ip.split('/')[0]),
                                   'ifconfig {0}'.format(egress),
                                 )
            for cmd in config_cmds_egress:
                os.system(cmd)
            index += 1
            if index == egress_iface_count:
               break
            egress_iface_count += 1
            egress_iface_num += 1


    @classmethod
    def acl_hosts_remove(cls, egress_iface_count = 1,  egress_iface_num = None):
        if egress_iface_num is None:
           egress_iface_num = cls.egress_iface
        n = 0
        for n in range(egress_iface_count):
           egress = cls.port_map[egress_iface_num]
           config_cmds_egress = ('ifconfig {} 0'.format(egress))
           os.system(config_cmds_egress)
           egress_iface_num += 1

#    @classmethod
    def acl_rule_traffic_send_recv(self, srcMac, dstMac, srcIp, dstIp, ingress =None, egress=None, ip_proto=None, dstPortNum = None, positive_test = True):
        if ingress is None:
           ingress = self.ingress_iface
        if egress is None:
           egress = self.egress_iface
        ingress = self.port_map[ingress]
        egress = self.port_map[egress]
        self.success = False if positive_test else True
        timeout = 10 if positive_test else 1
        count = 2 if positive_test else 1
        self.start_sending = True
        def recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True if positive_test else False
            sniff(count=count, timeout=timeout,
                  lfilter = lambda p: IP in p and p[IP].dst == dstIp.split('/')[0] and p[IP].src == srcIp.split('/')[0],
                  prn = recv_cb, iface = egress)
            self.start_sending = False

        t = threading.Thread(target = recv_task)
        t.start()
        L2 = Ether(src = srcMac, dst = dstMac)
        L3 = IP(src = srcIp.split('/')[0], dst = dstIp.split('/')[0])
        pkt = L2/L3
        log.info('Sending a packet with dst ip %s, src ip %s , dst mac %s src mac %s on port %s to verify if flows are correct' %
                 (dstIp.split('/')[0], srcIp.split('/')[0], dstMac, srcMac, ingress))
        while self.start_sending is True:
            sendp(pkt, count=50, iface = ingress)
        t.join()
        assert_equal(self.success, True)

    @classmethod
    def onos_load_config(cls, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_allow_rule(self):
        acl_rule = ACLTest()
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
	aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_allow_rule_with_24_bit_mask(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_PREFIX_24, dstIp =self.ACL_DST_IP_PREFIX_24, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_deny_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
	aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_deny_rule_with_24_bit_mask(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_PREFIX_24, dstIp =self.ACL_DST_IP_PREFIX_24, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_add_remove_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        status, code = acl_rule.remove_acl_rule(acl_Id[0])
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_add_remove_all_rules(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        status,code = acl_rule.adding_acl_rule('v4', srcIp='10.10.10.10/24', dstIp ='20.20.20.20/24', action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        status, _ = ACLTest.remove_acl_rule()
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_remove_all_rules_without_add(self):
        status, _ = ACLTest.remove_acl_rule()
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_allow_and_deny_rule_for_same_src_and_dst_ip(self):
        acl_rule = ACLTest()
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, False)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        status, _ = ACLTest.remove_acl_rule()
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_allow_rules_for_matched_dst_ips(self):
        acl_rule = ACLTest()
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp ='192.168.30.2/24', action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, False)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        status, _ = ACLTest.remove_acl_rule()
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_with_matching_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
	acl_rule = ACLTest()
        status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
	aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP')
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_with_matching_24bit_mask_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_PREFIX_24, dstIp =self.ACL_DST_IP_PREFIX_24, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP, ingress =ingress, egress = egress, ip_proto = 'UDP')
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_with_non_matching_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
	acl_rule = ACLTest()
        status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
	aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac, srcIp ='192.168.40.1/24', dstIp = self.ACL_DST_IP, ingress=ingress, egress = egress, ip_proto = 'UDP', positive_test = False )
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_deny_rule_with_matching_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_deny_rule_with_src_and_dst_ip_applying_24_bit_mask_for_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_PREFIX_24, dstIp =self.ACL_DST_IP_PREFIX_24, action = 'deny')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_PREFIX_24, dstIp = self.ACL_DST_IP_PREFIX_24,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_deny_rule_with_non_matching_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp ='192.168.40.1/24', dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_allow_and_deny_rules_with_matching_src_and_dst_ip_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        egress = self.CURRENT_PORT_NUM
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress ,ip_proto = 'UDP')
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP_RULE_2)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_RULE_2, dstIp =self.ACL_DST_IP_RULE_2, action = 'deny')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_RULE_2, dstIp = self.ACL_DST_IP_RULE_2,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        ### crossing checking that we should not receive allow acl rule traffic on onther host non matched traffic
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_for_l4_acl_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
	aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_for_remove_l4_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='245', action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        status, code = acl_rule.remove_acl_rule(acl_Id[0])
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_for_remove_l4_rules(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='567', action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='245', action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='ICMP', dstTpPort ='1',action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 3)
        status, _ = ACLTest.remove_acl_rule()
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    def test_acl_adding_specific_l4_and_all_l4_allow_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)

    def test_acl_adding_all_l4_and_specific_l4_allow_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='345', action = 'allow')
        if status is True:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_with_specific_l4_and_all_l4_deny_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)

    def test_acl_with_all_l4_and_specific_l4_deny_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='345', action = 'deny')
        if status is True:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_with_specific_l4_deny_and_all_l4_allow_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)

    def test_acl_deny_all_l4_and_allow_specific_l4_rule(self):
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='345', action = 'allow')
        if status is True:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
	log.info('Added ACL rules  = %s' %result.json()['aclRules'])
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)

    def test_acl_tcp_port_allow_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'allow')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 222)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 444, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_udp_port_allow_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='456', action = 'allow')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 456)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 654, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_icmp_port_allow_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='ICMP', dstTpPort ='1', action = 'allow')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'ICMP', dstPortNum = 1)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'ICMP', dstPortNum = 2, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_tcp_port_deny_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'deny')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 222, positive_test = False)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 444, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_udp_port_deny_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='654', action = 'deny')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 654, positive_test = False)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 444, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_icmp_port_deny_rule_for_matching_and_non_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='ICMP', dstTpPort ='1', action = 'deny')
        time.sleep(20)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL Rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'ICMP', dstPortNum = 1, positive_test = False)
        ## Non-matching traffic for TCP portocol testing
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'ICMP', dstPortNum = 2, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    def test_acl_two_allow_rules_for_tcp_port_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='TCP', dstTpPort ='222', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        egress = self.CURRENT_PORT_NUM
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 222)
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP_RULE_2)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_RULE_2, dstIp =self.ACL_DST_IP_RULE_2, ipProto ='TCP', dstTpPort ='345', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_RULE_2, dstIp = self.ACL_DST_IP_RULE_2,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 345)
        ### crossing checking that we should not receive allow acl rule traffic on onther host non matched traffic
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 222, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 2,  egress_iface_num = egress-1)

    def test_acl_two_allow_rules_for_udp_ports_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, ipProto ='UDP', dstTpPort ='987', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        egress = self.CURRENT_PORT_NUM
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 987)
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP_RULE_2)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_RULE_2, dstIp =self.ACL_DST_IP_RULE_2, ipProto ='TCP', dstTpPort ='345', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_RULE_2, dstIp = self.ACL_DST_IP_RULE_2,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 345)
        ### crossing checking that we should not receive allow acl rule traffic on onther host non matched traffic
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 987, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 2,  egress_iface_num = egress-1)

    def test_acl_two_allow_rules_for_src_ips_dst_ips_and_l4_ports_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        egress = self.CURRENT_PORT_NUM
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP')
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP_RULE_2)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_RULE_2, dstIp =self.ACL_DST_IP_RULE_2, ipProto ='TCP', dstTpPort ='345', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_RULE_2, dstIp = self.ACL_DST_IP_RULE_2,ingress =ingress, egress = egress, ip_proto = 'TCP', dstPortNum = 345)
        ### crossing checking that we should not receive allow acl rule traffic on onther host non matched traffic
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 987, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 2,  egress_iface_num = egress-1)

    def test_acl_allow_and_deny_rules_for_src_ips_dst_ips_and_l4_ports_matching_traffic(self):
        ingress = self.ingress_iface
        egress = self.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP, dstIp =self.ACL_DST_IP, action = 'deny')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 1)
        log.info('Added ACL rules = %s' %result.json()['aclRules'])
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        egress = self.CURRENT_PORT_NUM
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP_RULE_2)
        self.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        dstMac = host_ip_mac[0][1]
        self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.ACL_SRC_IP_RULE_2, dstIp =self.ACL_DST_IP_RULE_2, ipProto ='UDP', dstTpPort ='345', action = 'allow')
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules()
        aclRules1 = result.json()['aclRules']
        acl_Id = map(lambda d: d['id'], aclRules1)
        assert_equal(len(acl_Id), 2)
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP_RULE_2, dstIp = self.ACL_DST_IP_RULE_2,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 345)
        ### crossing checking that we should not receive allow acl rule traffic on onther host non matched traffic
        self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 987, positive_test = False)
        self.cliExit()
        self.acl_hosts_remove(egress_iface_count = 2,  egress_iface_num = egress-1)
