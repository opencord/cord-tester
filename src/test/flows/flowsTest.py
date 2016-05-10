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
from scapy.all import *
import time
import json
import threading
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl, get_mac
from OltConfig import OltConfig
log.setLevel('INFO')

class flows_exchange(unittest.TestCase):

    #Use the first available device id as our device id to program flows
    app = 'org.onosproject.cli'
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    default_port_map = { 
        PORT_TX_DEFAULT : INTF_TX_DEFAULT,
        PORT_RX_DEFAULT : INTF_RX_DEFAULT,
        INTF_TX_DEFAULT : PORT_TX_DEFAULT,
        INTF_RX_DEFAULT : PORT_RX_DEFAULT
        }

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = cls.default_port_map
        cls.device_id = 'of:' + get_mac() ##match against our device id

    def test_flow_mac(self):
        '''Add and verify flows with MAC selectors'''
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:00:01'
        ingress_mac = '00:00:00:00:00:02'
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethSrc = ingress_mac,
                            ethDst = egress_mac)
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(3)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
                self.success = True
            sniff(count=2, timeout=5, lfilter = lambda p: p.src == ingress_mac, 
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        pkt = Ether(src = ingress_mac, dst = egress_mac)/IP()
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ip(self):
        '''Add and verify flows with IPv4 selectors'''
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethType = '0x0800',
                            ipSrc = ('IPV4_SRC', ingress_map['ip']+'/32'),
                            ipDst = ('IPV4_DST', egress_map['ip']+'/32')
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(3)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5, 
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip'],
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)
