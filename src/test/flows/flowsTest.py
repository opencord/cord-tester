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
import os
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl, get_mac
from OltConfig import OltConfig
import random
from threading import current_thread
import collections
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

    def incmac(self, mac):
	tmp =  str(hex(int('0x'+mac,16)+1).split('x')[1])
	mac = '0'+ tmp if len(tmp) < 2 else tmp
	return mac

    def next_mac(self, mac):
        mac = mac.split(":")
        mac[5] = self.incmac(mac[5])

        if len(mac[5]) > 2:
	   mac[0] = self.incmac(mac[0])
	   mac[5] = '01'

        if len(mac[0]) > 2:
	   mac[0] = '01'
	   mac[1] = self.incmac(mac[1])
	   mac[5] = '01'
        return ':'.join(mac)

    def to_egress_mac(cls, mac):
        mac = mac.split(":")
        mac[4] = '01'

        return ':'.join(mac)

    def inc_ip(self, ip, i):

        ip[i] =str(int(ip[i])+1)
        return '.'.join(ip)


    def next_ip(self, ip):

        lst = ip.split('.')
        for i in (3,0,-1):
	    if int(lst[i]) < 255:
	       return self.inc_ip(lst, i)
	    elif int(lst[i]) == 255:
	       lst[i] = '0'
	       if int(lst[i-1]) < 255:
		  return self.inc_ip(lst,i-1)
	       elif int(lst[i-2]) < 255:
		  lst[i-1] = '0'
		  return self.inc_ip(lst,i-2)
	       else:
		  break

    def to_egress_ip(self, ip):
        lst=ip.split('.')
        lst[0] = '182'
        return '.'.join(lst)




    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = cls.default_port_map
        cls.device_id = 'of:' + get_mac() ##match against our device id

    def test_flow_mac(self):
        '''Test Add and verify flows with MAC selectors'''
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
        time.sleep(1)
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
        '''Test Add and verify flows with IPv4 selectors'''
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
        time.sleep(1)
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


    def test_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 9500 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 9000 }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            tcpSrc = ingress_map['tcp_port'],
                            tcpDst = egress_map['tcp_port']
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout=5, lfilter = lambda p: TCP in p and p[TCP].dport == egress_map['tcp_port']
			and p[TCP].sport == ingress_map['tcp_port'], prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = TCP(sport = ingress_map['tcp_port'], dport = egress_map['tcp_port'])
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 9500 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 9000 }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            udpSrc = ingress_map['udp_port'],
                            udpDst = egress_map['udp_port']
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=5,
             lfilter = lambda p: UDP in p and p[UDP].dport == egress_map['udp_port']
				and p[UDP].sport == ingress_map['udp_port'], prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = UDP(sport = ingress_map['udp_port'], dport = egress_map['udp_port'])
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    @nottest
    def test_flow_vlan(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:00:01'
        ingress_mac = '00:00:00:00:00:02'
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethSrc = ingress_mac,
                            ethDst = egress_mac,
			    vlan = 0x10)
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
                log.info('Pkt:%s', pkt.show())
                self.success = True
            sniff(count=2, timeout=5, lfilter = lambda p:p.src == ingress_mac,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        pkt = Ether(src = ingress_mac, dst = egress_mac)/Dot1Q(vlan = 0x10)/IP()
	log.info("Sending Packet:%s",pkt.show())
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ipv6(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethType = '0x86dd',
                            ipSrc = ('IPV6_SRC', ingress_map['ipv6'] + '/48'),
                            ipDst = ('IPV6_DST', egress_map['ipv6'] + '/48')
                            )

        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IPv6].src, pkt[IPv6].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IPv6 in p and p[IPv6].dst == egress_map['ipv6'] and p[IPv6].src == ingress_map['ipv6'],
                 prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'])
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ipv6_flow_label(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6flow_label = 25
                            )

        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s with flow label %s' %(pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].fl))
                self.success = True
            sniff(count=2, timeout=5, lfilter = lambda p: IPv6 in p and p[IPv6].dst == egress_map['ipv6']
		and p[IPv6].src == ingress_map['ipv6'] and p[IPv6].fl == 25, prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'], fl = 25)
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ipv6_extension_header(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6_extension = 0,
                            )

        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s, Extension Header Type %s' %(pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IPv6 in p and p[IPv6].nh == 0, prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'], nh = 0)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ipv6_available_extension_headers(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
	for i in [0, 60, 43, 44, 51, 50, 135]:
	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ipv6_extension = i,
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s, Extension Header Type %s' %(pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh))
                self.success = True
            sniff(count=2, timeout=5, lfilter = lambda p: IPv6 in p and p[IPv6].nh == i,
		    prn = recv_cb, iface = self.port_map[egress])

	for i in [0, 60, 43, 44, 51, 50, 135]:
	    self.success = False
	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'], nh = i)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()
	    assert_equal(self.success, True)


    def test_flow_dscp(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            dscp = 32
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']
			and p[IP].tos == 32,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = 32)
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_available_dscp(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
	dscp = [184, 0, 40, 48, 56, 72, 80, 88, 104, 112, 120, 136, 144, 152, 32, 64, 96, 128, 160, 192, 224]
	for i in dscp:
	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            dscp = i
	                            )
	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']
			and p[IP].tos == i,prn = recv_cb, iface = self.port_map[egress])

	for i in dscp:
	        self.success = False
	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = i)
	        pkt = L2/L3
	        log.info('Sending a packet to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()
	        assert_equal(self.success, True)

    def test_flow_ecn(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ecn = 1
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']
			and int(bin(p[IP].tos).split('b')[1][-2:],2) == 1,prn = recv_cb,
				iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = 1)
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_flow_available_ecn(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
	for i in range(4):
	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            ecn = i
	                            )
	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']
			and int(bin(p[IP].tos).split('b')[1][-2:],2) == i,prn = recv_cb,
				iface = self.port_map[egress])

	for i in range(4):
	        self.success = False
	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = i)
	        pkt = L2/L3
	        log.info('Sending a packet to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()
	        assert_equal(self.success, True)

    def test_flow_available_dscp_and_ecn(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
	dscp = [46, 0, 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38, 8, 16, 24, 32, 40, 48, 56]
	for i in dscp:
		for j in (0,1,2,3):
		        flow = OnosFlowCtrl(deviceId = self.device_id,
		                            egressPort = egress,
		                            ingressPort = ingress,
		                            dscp = i,
					    ecn = j
		                            )
		        result = flow.addFlow()
		        assert_equal(result, True)
		        ##wait for flows to be added to ONOS
		        time.sleep(1)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].tos == int(bin(i).split('b')[1]+ bin(j).split('b')[1],2)
			 ,prn = recv_cb, iface = self.port_map[egress])

	for i in dscp:
		for j in (0,1,2,3):

			self.success = False
			t = threading.Thread(target = mac_recv_task)
			t.start()
			L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
			L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = int(bin(i).split('b')[1]+ bin(j).split('b')[1],2))
			pkt = L2/L3
			log.info('Sending packets to verify if flows are correct')
			sendp(pkt, count=50, iface = self.port_map[ingress])
			t.join()
			assert_equal(self.success, True)

    def test_flow_icmp(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            icmpv4_type =  '3',
                            icmpv4_code =  8
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMP type %s, ICMP code %s' %(pkt[ICMP].type, pkt[ICMP].code))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMP in p and p[ICMP].type == 3 and p[ICMP].code == 8,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])/ICMP(type = 3, code = 8)
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmp_different_types(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
	icmp = {'11': [0, 1], '10': 0, '0': 0, '3': [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		'5': [1, 2, 3], '4': 0, '9': 0, '8': 0}
	for type,code in icmp.items():
	    if isinstance(code, list):
	       for i in code:
		   flow = OnosFlowCtrl(deviceId = self.device_id,
				    egressPort = egress,
				    ingressPort = ingress,
				    icmpv4_type =  type,
				    icmpv4_code =  i
				    )
		   result = flow.addFlow()
		   assert_equal(result, True)
		   ##wait for flows to be added to ONOS
		   time.sleep(1)
	    else:
		   flow = OnosFlowCtrl(deviceId = self.device_id,
				    egressPort = egress,
				    ingressPort = ingress,
				    icmpv4_type =  type,
				    icmpv4_code =  code
				    )
		   result = flow.addFlow()
		   assert_equal(result, True)
		   ##wait for flows to be added to ONOS
		   time.sleep(1)
	self.success = False

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMP type %s, ICMP code %s' %(pkt[ICMP].type, pkt[ICMP].code))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMP in p and p[ICMP].type == 3 and p[ICMP].code == 8,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])/ICMP(type = 3, code = 8)
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmpv6_EchoRequest(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002'}
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            icmpv6_type =  '128',
                            icmpv6_code =  0
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6EchoRequest].type, pkt[ICMPv6EchoRequest].code))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6EchoRequest in p and p[ICMPv6EchoRequest].type == 128 and p[ICMPv6EchoRequest].code == 0,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6EchoRequest()
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmpv6_EchoReply(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            icmpv6_type =  '129',
                            icmpv6_code =  0
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6EchoReply].type, pkt[ICMPv6EchoReply].code))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6EchoReply in p and p[ICMPv6EchoReply].type == 129 and p[ICMPv6EchoReply].code == 0,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6EchoReply()
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_flow_icmpv6_DestUnreachable(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
	for i in range(8):
	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            icmpv6_type =  '1',
	                            icmpv6_code =  i
	                            )
	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)
	for i in range(8):
	        self.success = False
	        def mac_recv_task():
	            def recv_cb(pkt):
	                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6DestUnreach].type, pkt[ICMPv6DestUnreach].code))
	                self.success = True
	            sniff(count=2, timeout=5,
	                  lfilter = lambda p: ICMPv6DestUnreach in p and p[ICMPv6DestUnreach].type == 1 and p[ICMPv6DestUnreach].code == i,
	                  prn = recv_cb, iface = self.port_map[egress])

	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6DestUnreach(code = i)
	        pkt = L2/L3
	        log.info('Sending packets to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()
	        assert_equal(self.success, True)

    def test_flow_icmpv6_PacketTooBig(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            icmpv6_type =  '2',
                            icmpv6_code =  0
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6PacketTooBig].type, pkt[ICMPv6PacketTooBig].code))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6PacketTooBig in p and p[ICMPv6PacketTooBig].type == 2 and p[ICMPv6PacketTooBig].code == 0,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6PacketTooBig()
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmpv6_TimeExceeded(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
	for i in range(2):
	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            icmpv6_type =  '3',
	                            icmpv6_code =  i
	                            )
	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)
	for i in range(2):
	        self.success = False
	        def mac_recv_task():
	            def recv_cb(pkt):
	                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6TimeExceeded].type, pkt[ICMPv6TimeExceeded].code))
	                self.success = True
	            sniff(count=2, timeout=5,
	                  lfilter = lambda p: ICMPv6TimeExceeded in p and p[ICMPv6TimeExceeded].type == 3 and p[ICMPv6TimeExceeded].code == i,
	                  prn = recv_cb, iface = self.port_map[egress])

	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6TimeExceeded(code = i)
	        pkt = L2/L3
	        log.info('Sending packets to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()
	        assert_equal(self.success, True)

    def test_flow_icmpv6_ParameterProblem(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
	for i in range(3):
	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            icmpv6_type =  '4',
	                            icmpv6_code =  i
	                            )
	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)
	for i in range(3):
	        self.success = False
	        def mac_recv_task():
	            def recv_cb(pkt):
	                log.info('Pkt seen with ICMPv6 type %s, ICMPv6 code %s' %(pkt[ICMPv6ParamProblem].type, pkt[ICMPv6ParamProblem].code))
	                self.success = True
	            sniff(count=2, timeout=5,
	                  lfilter = lambda p: ICMPv6ParamProblem in p and p[ICMPv6ParamProblem].type == 4 and p[ICMPv6ParamProblem].code == i,
	                  prn = recv_cb, iface = self.port_map[egress])

	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6ParamProblem(code = i)
	        pkt = L2/L3
	        log.info('Sending packets to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()
	        assert_equal(self.success, True)

    def test_flow_icmpv6_ND_Target_address(self):
        egress = 1
        ingress = 2
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002'}
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6_target =  '2001:db8:a0b:12f0:1010:1010:1010:1001')
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 Neighbor Discovery type %s, target address %s' %(pkt[ICMPv6ND_NS].type, pkt[ICMPv6ND_NS].tgt))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6ND_NS in p and p[ICMPv6ND_NS].tgt == '2001:db8:a0b:12f0:1010:1010:1010:1001',
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'])/ICMPv6ND_NS(tgt = '2001:db8:a0b:12f0:1010:1010:1010:1001')
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmpv6_ND_SLL(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002'}
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6_sll =   ingress_map['ether'])
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 Neighbor Discovery type %s, Source Link Layer address %s' %(pkt[ICMPv6ND_NS].type, pkt[ICMPv6NDOptSrcLLAddr].lladdr))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6NDOptSrcLLAddr in p and p[ICMPv6NDOptSrcLLAddr].lladdr == ingress_map['ether'],
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'])#, dst = ingress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6ND_NS(tgt =  egress_map['ipv6'])/ICMPv6NDOptSrcLLAddr(lladdr = ingress_map['ether'])
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_icmpv6_NA_TLL(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001'}
        ingress_map = { 'ether': '00:00:00:00:00:04','ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002'}
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6_tll =   egress_map['ether'])
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ICMPv6 Neighbor Advertisement type %s, Target Link Layer address %s' %(pkt[ICMPv6ND_NA].type, pkt[ICMPv6NDOptDstLLAddr].lladdr))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: ICMPv6NDOptDstLLAddr in p and p[ICMPv6NDOptDstLLAddr].lladdr == ingress_map['ether'],
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'])#, dst = ingress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'], dst = egress_map['ipv6'])/ICMPv6ND_NA(tgt =  ingress_map['ipv6'])/ICMPv6NDOptDstLLAddr(lladdr = ingress_map['ether'])
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_flow_ipv6_and_icmpv6(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethType = '0x86dd',
                            ipSrc = ('IPV6_SRC', ingress_map['ipv6'] + '/48'),
                            ipDst = ('IPV6_DST', egress_map['ipv6'] + '/48'),
			    icmpv6_type =  '128',
                            icmpv6_code =  0
                            )

        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IPv6].src, pkt[IPv6].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IPv6 in p and p[IPv6].dst == egress_map['ipv6'] and p[IPv6].src == ingress_map['ipv6']
			and p[ICMPv6EchoRequest].type == 128 and p[ICMPv6EchoRequest].code == 0, prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'])/ICMPv6EchoRequest()
        pkt = L2/L3
        log.info('Sending a packet to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_5_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'


	for i in range(0,5):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = False

	def mac_recv_task():
	    def recv_cb(pkt):
		log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		self.success = True
	    sniff(count=2, timeout=5, lfilter = lambda p: p.src == '00:00:00:00:00:02',
		    prn = recv_cb, iface = self.port_map[egress])

	t = threading.Thread(target = mac_recv_task)
	t.start()
	pkt = Ether(src = '00:00:00:00:00:02', dst = egress_mac)/IP()
	log.info('Sending packets to verify if flows are correct')
	sendp(pkt, count=50, iface = self.port_map[ingress])
	t.join()
        assert_equal(self.success, True)


    def test_500_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,500):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
	self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

		t = threading.Thread(target = mac_recv_task)
		t.start()
		pkt = Ether(src = random_src, dst = egress_mac)/IP()
		log.info('Sending packets to verify if flows are correct')
		sendp(pkt, count=50, iface = self.port_map[ingress])
		t.join()

	t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
	t2 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:' + hex(random.randrange(50,254)).split('x')[1])
	t3 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(16,100)).split('x')[1])
	t4 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(101,240)).split('x')[1])
	t5 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:f5')
	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()

	if len(success_dir) != 5:
		self.success = False

        assert_equal(self.success, True)


    def test_1k_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,1000):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = egress_mac)/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:' + hex(random.randrange(50,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:09')
        t4 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(16,150)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(151,250)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:' +  hex(random.randrange(16,150)).split('x')[1])
        t8 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:' +  hex(random.randrange(151,250)).split('x')[1])
        t9 = threading.Thread(target = verify_flow, args = '03:00:00:00:00:'+ hex(random.randrange(16,175)).split('x')[1])
        t10 = threading.Thread(target = verify_flow, args = '03:00:00:00:00:eb')
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)


    @nottest
    def test_10k_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}


	for i in range(0,10000):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = egress_mac)/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,21)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(17,21)).split('x')[1] +':00:00:00:00:' +
							hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(22,30)).split('x')[1] +':00:00:00:00:' +
							hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(31,38)).split('x')[1] +':00:00:00:00:' +
							hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '27:00:00:00:00:37')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_100k_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}


	for i in range(0,100000):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = egress_mac)/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,41)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(42,72)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(73,100)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(101,136)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '89:01:00:00:00:28')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)


    @nottest
    def test_1000k_flow_constant_dst_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}


	for i in range(0,1000000):
	    ingress_mac = self.next_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = egress_mac)/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,21)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(22,50)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(51,75)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(76,95)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '60:0f:00:00:00:91')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    def test_5_flow_constant_src_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:01'


	for i in range(0,5):
	    egress_mac = self.next_mac(egress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = False

	def mac_recv_task():
	    def recv_cb(pkt):
		log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		self.success = True
	    sniff(count=2, timeout=5, lfilter = lambda p: p.src == '00:00:00:00:00:01' and p.dst == '00:00:00:00:01:02',
		    prn = recv_cb, iface = self.port_map[egress])

	t = threading.Thread(target = mac_recv_task)
	t.start()
	pkt = Ether(src = ingress_mac, dst =  '00:00:00:00:01:02')/IP()
	log.info('Sending packets to verify if flows are correct')
	sendp(pkt, count=50, iface = self.port_map[ingress])
	t.join()
        assert_equal(self.success, True)

    def test_500_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,500):
	    ingress_mac = self.next_mac(ingress_mac)
	    egress_mac = self.to_egress_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True
        def verify_flow(*r):
	    random_src = ''.join(r)

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst =  self.to_egress_mac(random_src))/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:' + hex(random.randrange(50,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(16,100)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(101,240)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:f5')
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
	if len(success_dir) != 5:
                self.success = False

        assert_equal(self.success, True)

    def test_1k_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,1000):
	    ingress_mac = self.next_mac(ingress_mac)
	    egress_mac = self.to_egress_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True
        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
            pkt = Ether(src = random_src, dst =  self.to_egress_mac(random_src))/IP()
            log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:' + hex(random.randrange(50,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:09')
        t4 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(16,150)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' +  hex(random.randrange(151,250)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:' +  hex(random.randrange(16,150)).split('x')[1])
        t8 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:' +  hex(random.randrange(151,250)).split('x')[1])
        t9 = threading.Thread(target = verify_flow, args = '03:00:00:00:00:'+ hex(random.randrange(16,175)).split('x')[1])
        t10 = threading.Thread(target = verify_flow, args = '03:00:00:00:00:eb')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,10000):
	    ingress_mac = self.next_mac(ingress_mac)
	    egress_mac = self.to_egress_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True
        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = self.to_egress_mac(random_src))/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,21)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(17,21)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(22,30)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(31,38)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '27:00:00:00:00:37')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_100k_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,100000):
	    ingress_mac = self.next_mac(ingress_mac)
	    egress_mac = self.to_egress_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = self.to_egress_mac(random_src))/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,41)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(42,72)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(73,100)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(101,136)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '89:01:00:00:00:28')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_1000k_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	success_dir = {}

	for i in range(0,1000000):
	    ingress_mac = self.next_mac(ingress_mac)
	    egress_mac = self.to_egress_mac(ingress_mac)

	    flow = OnosFlowCtrl(deviceId = self.device_id,
			egressPort = egress,
			ingressPort = ingress,
			ethSrc = ingress_mac,
			ethDst = egress_mac)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

        def verify_flow(*r):
	    random_src = ''.join(r)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5, lfilter = lambda p: p.src == random_src,
			prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = Ether(src = random_src, dst = egress_mac)/IP()
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

        t1 = threading.Thread(target = verify_flow, args = '00:00:00:00:00:01')
        t2 = threading.Thread(target = verify_flow, args = '01:00:00:00:00:' + hex(random.randrange(16,254)).split('x')[1])
        t3 = threading.Thread(target = verify_flow, args = '02:00:00:00:00:'+ hex(random.randrange(16,254)).split('x')[1])
        t4 = threading.Thread(target = verify_flow, args = '05:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t5 = threading.Thread(target = verify_flow, args = '07:00:00:00:00:' +  hex(random.randrange(16,254)).split('x')[1])
        t6 = threading.Thread(target = verify_flow, args = hex(random.randrange(16,21)).split('x')[1] + ':00:00:00:00:08')
        t7 = threading.Thread(target = verify_flow, args = hex(random.randrange(22,50)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t8 = threading.Thread(target = verify_flow, args = hex(random.randrange(51,75)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t9 = threading.Thread(target = verify_flow, args = hex(random.randrange(76,95)).split('x')[1] +':00:00:00:00:' +
                                                        hex(random.randrange(16,254)).split('x')[1])

        t10 = threading.Thread(target = verify_flow, args = '60:0f:00:00:00:91')

        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    def test_rate_100_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	flows_added = 0
	stats_dir = collections.OrderedDict()
	running_time = 0


	for i in range(1,4):
	    start_time = time.time()
	    for j in range(0,100):
		ingress_mac = self.next_mac(ingress_mac)
		egress_mac = self.to_egress_mac(ingress_mac)

		flow = OnosFlowCtrl(deviceId = self.device_id,
			    egressPort = egress,
			    ingressPort = ingress,
			    ethSrc = ingress_mac,
			    ethDst = egress_mac)
		result = flow.addFlow()
		assert_equal(result, True)
		flows_added += 1
	##wait for flows to be added to ONOS
		time.sleep(1)
		log.info("%d flow added.",j+1)
	    end_time = time.time()
	    stats_dir['run '+str(i)] =  round((end_time - start_time),2)
	for t in stats_dir.items():
		log.info("----------------------------------------------")
		log.info("Statics for %s",t[0])
		log.info("----------------------------------------------")
		log.info("No. of flows added               Running Time ")
		log.info("       %d                             %s     " %(100, t[1]))
		running_time += float(t[1])

	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Final Statics")
	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Total No. of flows added               Total Running Time               Average no. of flows per second ")
	log.info("       %d                                %s second                               %d                     "
		%(flows_added, running_time, round(flows_added/running_time,0)))
	log.info("-------------------------------------------------------------------------------------------------------")



    def test_rate_500_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	flows_added = 0
	stats_dir = collections.OrderedDict()
	running_time = 0


	for i in range(1,4):
	    start_time = time.time()
	    for j in range(0,500):
		ingress_mac = self.next_mac(ingress_mac)
		egress_mac = self.to_egress_mac(ingress_mac)

		flow = OnosFlowCtrl(deviceId = self.device_id,
			    egressPort = egress,
			    ingressPort = ingress,
			    ethSrc = ingress_mac,
			    ethDst = egress_mac)
		result = flow.addFlow()
		assert_equal(result, True)
		flows_added += 1
	##wait for flows to be added to ONOS
		time.sleep(1)
		log.info("%d flow added.",j+1)
	    end_time = time.time()
	    stats_dir['run '+str(i)] =  round((end_time - start_time),2)
	for t in stats_dir.items():
	    log.info("----------------------------------------------")
	    log.info("Statics for %s",t[0])
	    log.info("----------------------------------------------")
	    log.info("No. of flows added               Running Time ")
	    log.info("       %d                             %s     " %(500, t[1]))
	    running_time += float(t[1])

	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Final Statics")
	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Total No. of flows added               Total Running Time               Average no. of flows per second ")
	log.info("       %d                                %s second                               %d                     "
		%(flows_added, running_time, round(flows_added/running_time,0)))
	log.info("-------------------------------------------------------------------------------------------------------")

    def test_rate_1k_flow_mac(self):
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:00'
        ingress_mac = '00:00:00:00:00:00'
	flows_added = 0
	stats_dir = collections.OrderedDict()
	running_time = 0


	for i in range(1,4):
	    start_time = time.time()
	    for j in range(0,1000):
		ingress_mac = self.next_mac(ingress_mac)
		egress_mac = self.to_egress_mac(ingress_mac)

		flow = OnosFlowCtrl(deviceId = self.device_id,
			    egressPort = egress,
			    ingressPort = ingress,
			    ethSrc = ingress_mac,
			    ethDst = egress_mac)
		result = flow.addFlow()
		assert_equal(result, True)
		flows_added += 1
	    ##wait for flows to be added to ONOS
		time.sleep(1)
		log.info("%d flow added.",j+1)
	    end_time = time.time()
	    stats_dir['run '+str(i)] =  round((end_time - start_time),2)
	for t in stats_dir.items():
	    log.info("----------------------------------------------")
	    log.info("Statics for %s",t[0])
	    log.info("----------------------------------------------")
	    log.info("No. of flows added               Running Time ")
	    log.info("       %d                             %s     " %(1000, t[1]))
	    running_time += float(t[1])

	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Final Statics")
	log.info("-------------------------------------------------------------------------------------------------------")
	log.info("Total No. of flows added               Total Running Time               Average no. of flows per second ")
	log.info("       %d                                %s second                               %d                     "
		%(flows_added, running_time, round(flows_added/running_time,0)))
	log.info("-------------------------------------------------------------------------------------------------------")


    def test_500_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	success_dir = {}

	for i in range(0,500):
	    ingress_map['ip'] = self.next_ip(ingress_map['ip'])
	    assert_not_equal(ingress_map['ip'], None)
	    egress_map['ip'] = self.to_egress_ip(ingress_map['ip'])

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ethType = '0x0800',
				ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
				ipDst = ('IPV4_DST', egress_map['ip']+'/8')
				)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    random_dst = self.to_egress_ip(random_src)

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
		    success_dir[current_thread().name] = True

		sniff(count=2, timeout=5,  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src
			,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = random_src, dst = random_dst)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = '192.0.0.1')
	t2 = threading.Thread(target = verify_flow, args = '192.0.0.' + str(random.randrange(10,100,1)))
	t3 = threading.Thread(target = verify_flow, args = '192.0.0.' +  str(random.randrange(101,255,1)))
	t4 = threading.Thread(target = verify_flow, args = '192.0.1.' +  str(random.randrange(1,235,1)))
	t5 = threading.Thread(target = verify_flow, args = '192.0.1.244')
	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()

	if len(success_dir) < 5 or len(success_dir) > 5:
		self.success = False
        assert_equal(self.success, True)


    @nottest
    def test_1k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	success_dir ={}

	for i in range(0,1000):
	    ingress_map['ip'] =  self.next_ip(ingress_map['ip'])
	    assert_not_equal(ingress_map['ip'], None)
	    egress_map['ip'] =  self.to_egress_ip(ingress_map['ip'])

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ethType = '0x0800',
				ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
				ipDst = ('IPV4_DST', egress_map['ip']+'/8')
				)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    random_dst = self.to_egress_ip(random_src)

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
		    success_dir[current_thread().name] = True

		sniff(count=2, timeout=5,  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src
			,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = random_src, dst = random_dst)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = '192.0.0.1')
	t2 = threading.Thread(target = verify_flow, args = '192.0.0.' + str(random.randrange(10,255,1)))
	t3 = threading.Thread(target = verify_flow, args = '192.0.1.' +  str(random.randrange(1,100,1)))
	t4 = threading.Thread(target = verify_flow, args = '192.0.1.' +  str(random.randrange(101,255,1)))
	t5 = threading.Thread(target = verify_flow, args = '192.0.2.' +  str(random.randrange(1,100,1)))
	t6 = threading.Thread(target = verify_flow, args = '192.0.2.' +  str(random.randrange(101,255,1)))
	t7 = threading.Thread(target = verify_flow, args = '192.0.3.' +  str(random.randrange(1,100,1)))
	t8 = threading.Thread(target = verify_flow, args = '192.0.3.' +  str(random.randrange(101,200,1)))
	t9 = threading.Thread(target = verify_flow, args = '192.0.'+  str(random.randrange(0,3,1)) + '.' +
				str(random.randrange(1,255,1)))
        t10 = threading.Thread(target = verify_flow, args = '192.0.3.232')

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
		self.success = False
        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	success_dir = {}

	for i in range(0,10000):
	    ingress_map['ip'] =  self.next_ip(ingress_map['ip'])
	    assert_not_equal(ingress_map['ip'], None)
	    egress_map['ip'] =  self.to_egress_ip(ingress_map['ip'])

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ethType = '0x0800',
				ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
				ipDst = ('IPV4_DST', egress_map['ip']+'/8')
				)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    random_dst = self.to_egress_ip(random_src)

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src
		      ,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = random_src, dst = random_dst)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = '192.0.0.1')
	t2 = threading.Thread(target = verify_flow, args = '192.0.0.' + str(random.randrange(1,255,1)))
	t3 = threading.Thread(target = verify_flow, args = '192.0.5.' +  str(random.randrange(1,255,1)))
	t4 = threading.Thread(target = verify_flow, args = '192.0.10.' +  str(random.randrange(1,255,1)))
	t5 = threading.Thread(target = verify_flow, args = '192.0.15.' +  str(random.randrange(1,255,1)))
	t6 = threading.Thread(target = verify_flow, args = '192.0.20.' +  str(random.randrange(1,255,1)))
	t7 = threading.Thread(target = verify_flow, args = '192.0.25.' +  str(random.randrange(1,255,1)))
	t8 = threading.Thread(target = verify_flow, args = '192.0.30.' +  str(random.randrange(1,255,1)))
	t9 = threading.Thread(target = verify_flow, args = '192.0.'+  str(random.randrange(0,39,1)) + '.' +
				str(random.randrange(1,255,1)))
        t10 = threading.Thread(target = verify_flow, args = '192.0.39.16')

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
		self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_100k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	success_dir = {}

	for i in range(0,100000):
	    ingress_map['ip'] =  self.next_ip(ingress_map['ip'])
	    assert_not_equal(ingress_map['ip'], None)
	    egress_map['ip'] =  self.to_egress_ip(ingress_map['ip'])

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ethType = '0x0800',
				ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
				ipDst = ('IPV4_DST', egress_map['ip']+'/8')
				)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    random_dst = self.to_egress_ip(random_src)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src
			,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = random_src, dst = random_dst)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = '192.0.0.1')
	t2 = threading.Thread(target = verify_flow, args = '192.0.0.' + str(random.randrange(1,255,1)))
	t3 = threading.Thread(target = verify_flow, args = '192.0.50.' +  str(random.randrange(1,255,1)))
	t4 = threading.Thread(target = verify_flow, args = '192.0.100.' +  str(random.randrange(1,255,1)))
	t5 = threading.Thread(target = verify_flow, args = '192.0.150.' +  str(random.randrange(1,255,1)))
	t6 = threading.Thread(target = verify_flow, args = '192.0.200.' +  str(random.randrange(1,255,1)))
	t7 = threading.Thread(target = verify_flow, args = '192.0.250.' +  str(random.randrange(1,255,1)))
	t8 = threading.Thread(target = verify_flow, args = '192.1.'+str(random.randrange(1,75,1)) + '.'
							+ str(random.randrange(1,255,1)))
	t9 = threading.Thread(target = verify_flow, args = '192.1.'+str(random.randrange(76,134,1)) + '.'
							+ str(random.randrange(1,255,1)))
        t10 = threading.Thread(target = verify_flow, args = '192.1.134.160')

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
		self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_1000k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	success_dir = {}

	for i in range(0,1000000):
	    ingress_map['ip'] =  self.next_ip(ingress_map['ip'])
	    assert_not_equal(ingress_map['ip'], None)
	    egress_map['ip'] =  self.to_egress_ip(ingress_map['ip'])

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				ethType = '0x0800',
				ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
				ipDst = ('IPV4_DST', egress_map['ip']+'/8')
				)
	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)
        self.success = True

	def verify_flow(*r):
	    random_src = ''.join(r)
	    random_dst = self.to_egress_ip(random_src)
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
		    success_dir[current_thread().name] = True

		sniff(count=2, timeout=5,  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src
			,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = random_src, dst = random_dst)
	    pkt = L2/L3
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = '192.0.0.1')
	t2 = threading.Thread(target = verify_flow, args = '192.0.50.' + str(random.randrange(1,255,1)))
	t3 = threading.Thread(target = verify_flow, args = '192.0.100.' +  str(random.randrange(1,255,1)))
	t4 = threading.Thread(target = verify_flow, args = '192.0.150.' +  str(random.randrange(1,255,1)))
	t5 = threading.Thread(target = verify_flow, args = '192.0.200.' +  str(random.randrange(1,255,1)))
	t6 = threading.Thread(target = verify_flow, args = '192.0.250.' +  str(random.randrange(1,255,1)))
	t7 = threading.Thread(target = verify_flow, args = '192.0.250.' +  str(random.randrange(1,255,1)))
	t8 = threading.Thread(target = verify_flow, args = '192.1.'+str(random.randrange(1,150,1)) + '.'
							+ str(random.randrange(1,255,1)))
	t9 = threading.Thread(target = verify_flow, args = '192.1.'+str(random.randrange(152,255,1)) + '.'
							+ str(random.randrange(1,255,1)))
        t10 = threading.Thread(target = verify_flow, args = '192.15.66.64')

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
		self.success = False

        assert_equal(self.success, True)

    def test_500_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 1100 }
	success_dir = {}

	for i in range(0,500):
	    ingress_map['tcp_port'] += 1
	    egress_map['tcp_port'] += 1

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				tcpSrc = ingress_map['tcp_port'],
				tcpDst = egress_map['tcp_port']
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d Flow added",i+1)
        self.success = True

	def verify_flow(*r):
	    random_sport = int(''.join(r))
	    random_dport = random_sport + 2000
	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,
		      lfilter = lambda p: TCP in p and p[TCP].dport == random_dport and p[TCP].sport == random_sport                    			  ,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	    L4 = TCP(sport = random_sport, dport = random_dport)
	    pkt = L2/L3/L4
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()
	t1 = threading.Thread(target = verify_flow, args = str(1101))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(1110,1250,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(1251,1400,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(1401,1590,1)))
	t5 = threading.Thread(target = verify_flow, args = str(1600))

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()

	if len(success_dir) != 5:
                self.success = False

        assert_equal(self.success, True)

    def test_1k_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 1100 }
	success_dir = {}

	for i in range(0,1000):
	    ingress_map['tcp_port'] += 1
	    egress_map['tcp_port'] += 1

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				tcpSrc = ingress_map['tcp_port'],
				tcpDst = egress_map['tcp_port']
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)

        self.success = True

	def verify_flow(*r):
	    random_sport = int(''.join(r))
	    random_dport = random_sport + 2000

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,
		      lfilter = lambda p: TCP in p and p[TCP].dport == random_dport and p[TCP].sport == random_sport                    			  ,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	    L4 = TCP(sport = random_sport, dport = random_dport)
	    pkt = L2/L3/L4
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = str(1101))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(1110,1350,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(1351,1500,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(1501,1700,1)))
	t5 = threading.Thread(target = verify_flow, args = str(random.randrange(1701,1900,1)))
	t6 = threading.Thread(target = verify_flow, args = str(random.randrange(1901,2000,1)))
	t7 = threading.Thread(target = verify_flow, args = str(random.randrange(2000,2050,1)))
	t8 = threading.Thread(target = verify_flow, args = str(random.randrange(2050,2080,1)))
	t9 = threading.Thread(target = verify_flow, args = str(random.randrange(1102,2100,1)))
	t10 = threading.Thread(target = verify_flow, args = str(2100))


	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 31000 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 11000 }
	success_dir = {}

	for i in range(0,10000):
	    ingress_map['tcp_port'] += 1
	    egress_map['tcp_port'] += 1

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				tcpSrc = ingress_map['tcp_port'],
				tcpDst = egress_map['tcp_port']
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)

        self.success = True

	def verify_flow(*r):
	    random_sport = int(''.join(r))
	    random_dport = random_sport + 20000

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,
		      lfilter = lambda p: TCP in p and p[TCP].dport == random_dport
			    and p[TCP].sport == random_sport,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	    L4 = TCP(sport = random_sport, dport = random_dport)
	    pkt = L2/L3/L4
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = str(11001))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(11110,12501,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(12510,14001,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(14010,15900,1)))
	t5 = threading.Thread(target = verify_flow, args = str(random.randrange(16000,17000,1)))
	t6 = threading.Thread(target = verify_flow, args = str(random.randrange(17001,18000,1)))
	t7 = threading.Thread(target = verify_flow, args = str(random.randrange(18000,19000,1)))
	t8 = threading.Thread(target = verify_flow, args = str(random.randrange(19000,20980,1)))
	t9 = threading.Thread(target = verify_flow, args = str(random.randrange(11002,21000,1)))
	t10 = threading.Thread(target = verify_flow, args = str(21000))


	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    def test_500_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 1100 }
	success_dir = {}

	for i in range(0,500):
	    ingress_map['udp_port'] += 1
	    egress_map['udp_port'] += 1

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				udpSrc = ingress_map['udp_port'],
				udpDst = egress_map['udp_port']
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)

        self.success = True

	def verify_flow(*r):
	    random_sport = int(''.join(r))
	    random_dport = random_sport + 2000

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,
		      lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport                    			  ,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	    L4 = UDP(sport = random_sport, dport = random_dport)
	    pkt = L2/L3/L4
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = str(1101))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(1110,1250,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(1251,1400,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(1401,1590,1)))
	t5 = threading.Thread(target = verify_flow, args = str(1600))


	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()

	if len(success_dir) != 5:
                self.success = False

        assert_equal(self.success, True)

    def test_1k_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 1100 }
	success_dir = {}

	for i in range(0,100000):
	    ingress_map['udp_port'] += 1
	    egress_map['udp_port'] += 1

	    flow = OnosFlowCtrl(deviceId = self.device_id,
				egressPort = egress,
				ingressPort = ingress,
				udpSrc = ingress_map['udp_port'],
				udpDst = egress_map['udp_port']
				)

	    result = flow.addFlow()
	    assert_equal(result, True)
	    ##wait for flows to be added to ONOS
	    time.sleep(1)
	    log.info("%d flow added.",i+1)

        self.success = True

	def verify_flow(*r):
	    random_sport = int(''.join(r))
	    random_dport = random_sport + 2000

	    def mac_recv_task():
		def recv_cb(pkt):
		    log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
		    success_dir[current_thread().name] = True
		sniff(count=2, timeout=5,
		      lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport                    			  ,prn = recv_cb, iface = self.port_map[egress])

	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	    L4 = UDP(sport = random_sport, dport = random_dport)
	    pkt = L2/L3/L4
	    log.info('Sending packets to verify if flows are correct')
	    sendp(pkt, count=50, iface = self.port_map[ingress])
	    t.join()

	t1 = threading.Thread(target = verify_flow, args = str(1101))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(1110,1350,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(1351,1500,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(1501,1700,1)))
	t5 = threading.Thread(target = verify_flow, args = str(random.randrange(1701,1900,1)))
	t6 = threading.Thread(target = verify_flow, args = str(random.randrange(1901,2000,1)))
	t7 = threading.Thread(target = verify_flow, args = str(random.randrange(2000,2050,1)))
	t8 = threading.Thread(target = verify_flow, args = str(random.randrange(2050,2080,1)))
	t9 = threading.Thread(target = verify_flow, args = str(random.randrange(1102,2100,1)))
	t10 = threading.Thread(target = verify_flow, args = str(2100))

	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
                self.success = False

        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 31000 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 11000 }
	success_dir = {}

	for i in range(0,10000):
		ingress_map['udp_port'] += 1
		egress_map['udp_port'] += 1

	        flow = OnosFlowCtrl(deviceId = self.device_id,
	                            egressPort = egress,
	                            ingressPort = ingress,
	                            udpSrc = ingress_map['udp_port'],
	                            udpDst = egress_map['udp_port']
	                            )

	        result = flow.addFlow()
	        assert_equal(result, True)
	        ##wait for flows to be added to ONOS
	        time.sleep(1)
		log.info("%d flow added.",i+1)

        self.success = True

	def verify_flow(*r):
		random_sport = int(''.join(r))
		random_dport = random_sport + 20000

	        def mac_recv_task():

	            def recv_cb(pkt):
	                log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
			success_dir[current_thread().name] = True
	            sniff(count=2, timeout=5,
	                  lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport                    			  ,prn = recv_cb, iface = self.port_map[egress])

	        t = threading.Thread(target = mac_recv_task)
	        t.start()
	        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
	        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
	        L4 = UDP(sport = random_sport, dport = random_dport)
	        pkt = L2/L3/L4
	        log.info('Sending packets to verify if flows are correct')
	        sendp(pkt, count=50, iface = self.port_map[ingress])
	        t.join()

	t1 = threading.Thread(target = verify_flow, args = str(11001))
	t2 = threading.Thread(target = verify_flow, args = str(random.randrange(11110,12501,1)))
	t3 = threading.Thread(target = verify_flow, args = str(random.randrange(12510,14001,1)))
	t4 = threading.Thread(target = verify_flow, args = str(random.randrange(14010,15900,1)))
	t5 = threading.Thread(target = verify_flow, args = str(random.randrange(16000,17000,1)))
	t6 = threading.Thread(target = verify_flow, args = str(random.randrange(17001,18000,1)))
	t7 = threading.Thread(target = verify_flow, args = str(random.randrange(18000,19000,1)))
	t8 = threading.Thread(target = verify_flow, args = str(random.randrange(19000,20980,1)))
	t9 = threading.Thread(target = verify_flow, args = str(random.randrange(11002,21000,1)))
	t10 = threading.Thread(target = verify_flow, args = str(21000))


	t1.start()
	t2.start()
	t3.start()
	t4.start()
	t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()

	t1.join()
	t2.join()
	t3.join()
	t4.join()
	t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()

	if len(success_dir) != 10:
                self.success = False
        assert_equal(self.success, True)
