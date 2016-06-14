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
import random
from threading import current_thread
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
        time.sleep(3)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: TCP in p and p[TCP].dport == egress_map['tcp_port'] and p[TCP].sport == ingress_map['tcp_port']                    ,prn = recv_cb, iface = self.port_map[egress])

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
        time.sleep(3)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: UDP in p and p[UDP].dport == egress_map['udp_port'] and p[UDP].sport == ingress_map['udp_port']                    ,prn = recv_cb, iface = self.port_map[egress])

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
	if len(success_dir) < 5 or len(success_dir) > 5:
	    self.success = False
	else:
	    for t in success_dir.items():
		self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	    self.success = False
        else:
	    for t in success_dir.items():
		self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 5 or len(success_dir) > 5:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	    self.success = False
        else:
	    for t in success_dir.items():
		self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        if len(success_dir) < 10 or len(success_dir) > 10:
	   self.success = False
        else:
	   for t in success_dir.items():
	       self.success = self.success and t[1]
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
        self.success = False
	random_src = '192.0.0.' + str(random.randrange(1,254,1))
	random_dst = self.to_egress_ip(random_src)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = random_src, dst = random_dst)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def test_1k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }

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
        self.success = False
	random_src = '192.0.0.' + str(random.randrange(1,254,1))
	random_dst =  self.to_egress_ip(random_src)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = random_src, dst = random_dst)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }

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
        self.success = False
	random_src = '192.0.0.' + str(random.randrange(1,254,1))
	random_dst =  self.to_egress_ip(random_src)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = random_src, dst = random_dst)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    @nottest
    def test_100k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }

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
        self.success = False
	random_src = '192.0.0.' + str(random.randrange(1,254,1))
	random_dst =  self.to_egress_ip(random_src)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = random_src, dst = random_dst)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    @nottest
    def test_1000k_flow_ip(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }

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
        self.success = False
	random_src = '192.0.0.' + str(random.randrange(1,254,1))
	random_dst =  self.to_egress_ip(random_src)

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == random_dst and p[IP].src == random_src,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = random_src, dst = random_dst)
        pkt = L2/L3
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_500_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 1100 }

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

        self.success = False
	random_sport = random.randrange(1101,1600,1)
	random_dport = random_sport + 2000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: TCP in p and p[TCP].dport == random_dport and p[TCP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = TCP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_1k_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 1100 }

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

        self.success = False
	random_sport = random.randrange(1101,2100,1)
	random_dport = random_sport + 2000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: TCP in p and p[TCP].dport == random_dport and p[TCP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = TCP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_tcp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 31000 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 11000 }

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

        self.success = False
	random_sport = random.randrange(11001,21000,1)
	random_dport = random_sport + 20000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: TCP in p and p[TCP].dport == random_dport and p[TCP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = TCP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_500_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 1100 }

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

        self.success = False
	random_sport = random.randrange(1101,1600,1)
	random_dport = random_sport + 2000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = UDP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)


    def test_1k_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 3100 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 1100 }

	for i in range(0,1000):
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

        self.success = False
	random_sport = random.randrange(1101,2100,1)
	random_dport = random_sport + 2000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = UDP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    @nottest
    def test_10k_flow_udp_port(self):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 31000 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 11000 }

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

        self.success = False
	random_sport = random.randrange(11001,21000,1)
	random_dport = random_sport + 20000

        def mac_recv_task():

            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: UDP in p and p[UDP].dport == random_dport and p[UDP].sport == random_sport
		  ,prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = mac_recv_task)
        t.start()
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = UDP(sport = random_sport, dport = random_dport)
        pkt = L2/L3/L4
        log.info('Sending packets to verify if flows are correct')
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)
