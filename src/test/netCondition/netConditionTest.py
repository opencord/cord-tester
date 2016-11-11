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
from threading import Timer
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from scapy.all import *
import time, monotonic
import os, sys
import tempfile
import random
import Queue
import threading
from IGMP import *
from McastTraffic import *
from Stats import Stats
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from Channels import IgmpChannel
from EapTLS import TLSAuthTest
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *
log.setLevel('INFO')
from EapolAAA import *
from enum import *
import noseTlsAuthHolder as tlsAuthHolder
from tls_cert import Key
from socket import *
from CordTestServer import cord_test_radius_restart
import struct
import scapy
from CordTestBase import CordTester
from CordContainer import *
from CordLogger import CordLogger
import re
from random import randint
from time import sleep

import json
from OnosFlowCtrl import OnosFlowCtrl
from OltConfig import OltConfig
from threading import current_thread
import collections

class IGMPTestState:

      def __init__(self, groups = [], df = None, state = 0):
            self.df = df
            self.state = state
            self.counter = 0
            self.groups = groups
            self.group_map = {} ##create a send/recv count map
            for g in groups:
                self.group_map[g] = (Stats(), Stats())

      def update(self, group, tx = 0, rx = 0, t = 0):
            self.counter += 1
            index = 0 if rx == 0 else 1
            v = tx if rx == 0 else rx
            if self.group_map.has_key(group):
                  self.group_map[group][index].update(packets = v, t = t)

      def update_state(self):
          self.state = self.state ^ 1

class netCondition_exchange(CordLogger):

    V_INF1 = 'veth0'
    V_INF2 = 'veth1'
    MGROUP1 = '239.1.2.3'
    MGROUP2 = '239.2.2.3'
    MINVALIDGROUP1 = '255.255.255.255'
    MINVALIDGROUP2 = '239.255.255.255'
    MMACGROUP1 = "01:00:5e:01:02:03"
    MMACGROUP2 = "01:00:5e:02:02:03"
    IGMP_DST_MAC = "01:00:5e:00:00:16"
    IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
    IP_SRC = '1.2.3.4'
    IP_DST = '224.0.0.22'
    NEGATIVE_TRAFFIC_STATUS = 1
    igmp_eth = Ether(dst = IGMP_DST_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST)
    IGMP_TEST_TIMEOUT = 5
    IGMP_QUERY_TIMEOUT = 60
    MCAST_TRAFFIC_TIMEOUT = 10
    TEST_TIMEOUT_DELAY = 340
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    app_igmp = 'org.opencord.igmp'
    olt_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json')
    ROVER_TEST_TIMEOUT = 10 #3600*86
    ROVER_TIMEOUT = (ROVER_TEST_TIMEOUT - 100)
    ROVER_JOIN_TIMEOUT = 60

    app_tls = 'org.opencord.aaa'
    TLS_TIMEOUT = 20
    CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIEyTCCA7GgAwIBAgIJAM6l2jUG56pLMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UE
ChMKQ2llbmEgSW5jLjEeMBwGCSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYw
JAYDVQQDEx1FeGFtcGxlIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNjAzMTEx
ODUzMzVaFw0xNzAzMDYxODUzMzVaMIGLMQswCQYDVQQGEwJVUzELMAkGA1UECBMC
Q0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UEChMKQ2llbmEgSW5jLjEeMBwG
CSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYwJAYDVQQDEx1FeGFtcGxlIENl
cnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL9Jv54TkqycL3U2Fdd/y5NXdnPVXwAVV3m6I3eIffVCv8eS+mwlbl9dnbjo
qqlGEgA3sEg5HtnKoW81l3PSyV/YaqzUzbcpDlgWlbNkFQ3nVxh61gSU34Fc4h/W
plSvCkwGSbV5udLtEe6S9IflP2Fu/eXa9vmUtoPqDk66p9U/nWVf2H1GJy7XanWg
wke+HpQvbzoSfPJS0e5Rm9KErrzaIkJpqt7soW+OjVJitUax7h45RYY1HHHlbMQ0
ndWW8UDsCxFQO6d7nsijCzY69Y8HarH4mbVtqhg3KJevxD9UMRy6gdtPMDZLah1c
LHRu14ucOK4aF8oICOgtcD06auUCAwEAAaOCASwwggEoMB0GA1UdDgQWBBQwEs0m
c8HARTVp21wtiwgav5biqjCBwAYDVR0jBIG4MIG1gBQwEs0mc8HARTVp21wtiwga
v5biqqGBkaSBjjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQH
EwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5hIEluYy4xHjAcBgkqhkiG9w0BCQEW
D2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBB
dXRob3JpdHmCCQDOpdo1BueqSzAMBgNVHRMEBTADAQH/MDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5jb20vZXhhbXBsZV9jYS5jcmwwDQYJKoZI
hvcNAQELBQADggEBAK+fyAFO8CbH35P5mOX+5wf7+AeC+5pwaFcoCV0zlfwniANp
jISgcIX9rcetLxeYRAO5com3+qLdd9dGVNL0kwufH4QhlSPErG7OLHHAs4JWVhUo
bH3lK9lgFVlnCDBtQhslzqScR64SCicWcQEjv3ZMZsJwYLvl8unSaKz4+LVPeJ2L
opCpmZw/V/S2NhBbe3QjTiRPmDev2gbaO4GCfi/6sCDU7UO3o8KryrkeeMIiFIej
gfwn9fovmpeqCEyupy2JNNUTJibEuFknwx7JAX+htPL27nEgwV1FYtwI3qLiZqkM
729wo9cFSslJNZBu+GsBP5LszQSuvNTDWytV+qY=
-----END CERTIFICATE-----'''

    def onos_aaa_config(self):
        aaa_dict = {'apps' : { 'org.onosproject.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                   'radiusIp': '172.17.0.2' } } } }
        radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
        aaa_dict['apps']['org.onosproject.aaa']['AAA']['radiusIp'] = radius_ip
        self.onos_ctrl.activate()
        time.sleep(2)
        self.onos_load_tls_config(aaa_dict)

    def onos_load_tls_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('Configure request for AAA returned status %d' %code)
            assert_equal(status, True)
            time.sleep(3)

    @classmethod
    def setUpClass(cls):
          cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
          cls.port_map, _ = cls.olt.olt_port_map()
          OnosCtrl.cord_olt_config(cls.olt.olt_device_data())
          cls.device_id = OnosCtrl.get_device_id()

    @classmethod
    def tearDownClass(cls): pass

    def setUp_igmp(self):
        ''' Activate the igmp app'''
        apps = self.app_igmp
        self.onos_ctrl = OnosCtrl(apps)
#        self.onos_ctrl = OnosCtrl(self.app_tls)
        self.onos_aaa_config()
	self.onos_ctrl.activate()
        self.igmp_channel = IgmpChannel()

    def setUp_tls(self):
        ''' Activate the igmp app'''
        apps = self.app_tls
        self.onos_ctrl = OnosCtrl(apps)
        self.onos_aaa_config()

    def tearDown(self):
        '''Deactivate the dhcp app'''
        apps = [self.app_igmp, self.app_tls]
        for app in apps:
            onos_ctrl = OnosCtrl(app)
            onos_ctrl.deactivate()
#        log.info('Restarting the Radius container in the setup after running every subscriber test cases by default')
#        rest = Container('cord-radius', 'cord-test/radius',)
#        rest.restart('cord-radius','10')
#        radius = Radius()
#        radius_ip = radius.ip()
#        print('Radius server is running with IP %s' %radius_ip)
        #os.system('ifconfig '+INTF_RX_DEFAULT+' up')

    def onos_load_igmp_config(self, config):
	log.info('onos load config is %s'%config)
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    def onos_ssm_table_load(self, groups, src_list = ['1.2.3.4'],flag = False):
          ssm_dict = {'apps' : { 'org.onosproject.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.onosproject.igmp']['ssmTranslate']
	  if flag: #to maintain seperate group-source pair.
	      for i in range(len(groups)):
		  d = {}
		  d['source'] = src_list[i] or '0.0.0.0'
		  d['group'] = groups[i]
		  ssm_xlate_list.append(d)
	  else:
              for g in groups:
                  for s in src_list:
                      d = {}
                      d['source'] = s or '0.0.0.0'
                      d['group'] = g
                      ssm_xlate_list.append(d)
          self.onos_load_igmp_config(ssm_dict)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          self.igmp_channel.cord_port_table_load(cord_port_map)
          time.sleep(2)

    def mcast_ip_range(self,start_ip = '224.0.1.0', end_ip = '224.0.1.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range

    def random_mcast_ip(self,start_ip = '224.0.1.0', end_ip = '224.0.1.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return random.choice(ip_range)

    def source_ip_range(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range

    def randomsourceip(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return random.choice(ip_range)

    def get_igmp_intf(self):
        inst = os.getenv('TEST_INSTANCE', None)
        if not inst:
            return 'veth0'
        inst = int(inst) + 1
        if inst >= self.port_map['uplink']:
            inst += 1
        if self.port_map.has_key(inst):
              return self.port_map[inst]
        return 'veth0'

    def igmp_verify_join(self, igmpStateList):
        sendState, recvState = igmpStateList
        ## check if the send is received for the groups
        for g in sendState.groups:
            tx_stats = sendState.group_map[g][0]
            tx = tx_stats.count
            assert_greater(tx, 0)
            rx_stats = recvState.group_map[g][1]
            rx = rx_stats.count
            assert_greater(rx, 0)
            log.info('Receive stats %s for group %s' %(rx_stats, g))

        log.info('IGMP test verification success')

    def igmp_verify_leave(self, igmpStateList, leave_groups):
        sendState, recvState = igmpStateList[0], igmpStateList[1]
        ## check if the send is received for the groups
        for g in sendState.groups:
            tx_stats = sendState.group_map[g][0]
            rx_stats = recvState.group_map[g][1]
            tx = tx_stats.count
            rx = rx_stats.count
            assert_greater(tx, 0)
            if g not in leave_groups:
                log.info('Received %d packets for group %s' %(rx, g))
        for g in leave_groups:
            rx = recvState.group_map[g][1].count
            assert_equal(rx, 0)

        log.info('IGMP test verification success')

    def mcast_traffic_timer(self):
          self.mcastTraffic.stopReceives()

    def send_mcast_cb(self, send_state):
        for g in send_state.groups:
            send_state.update(g, tx = 1)
        return 0

    ##Runs in the context of twisted reactor thread
    def igmp_recv(self, igmpState, iface = 'veth0'):
        p = self.recv_socket.recv()
        try:
              send_time = float(p.payload.load)
              recv_time = monotonic.monotonic()
        except:
              log.info('Unexpected Payload received: %s' %p.payload.load)
              return 0
        #log.info( 'Recv in %.6f secs' %(recv_time - send_time))
        igmpState.update(p.dst, rx = 1, t = recv_time - send_time)
        return 0

    def send_igmp_join(self, groups, src_list = ['1.2.3.4'], record_type=IGMP_V3_GR_TYPE_INCLUDE,
                       ip_pkt = None, iface = 'veth0', ssm_load = False, delay = 1):
        if ssm_load is True:
              self.onos_ssm_table_load(groups, src_list)
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype= record_type, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface=iface)
        if delay != 0:
            time.sleep(delay)


    def send_igmp_join_negative(self, groups, src_list = ['1.2.3.4'], record_type=IGMP_V3_GR_TYPE_INCLUDE,
                       ip_pkt = None, iface = 'veth0', ssm_load = False, delay = 1, ip_src = None, invalid_igmp_join = None ):
        if ssm_load is True:
              self.onos_ssm_table_load(groups, src_list)
        if invalid_igmp_join == 'igmp_type':
              igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT_NEGATIVE, max_resp_code=30,
                            gaddr=self.IP_DST)
        else:
              igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        if invalid_igmp_join == 'record_type':
           record_type = IGMP_V3_GR_TYPE_INCLUDE_NEGATIVE

        for g in groups:
              gr = IGMPv3gr(rtype= record_type, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              if ip_src is None:
                 ip_pkt = self.igmp_eth/self.igmp_ip
              else:
                 igmp_ip_src = IP(dst = self.IP_DST, src = ip_src)
                 ip_pkt = self.igmp_eth/igmp_ip_src
        pkt = ip_pkt/igmp
        if invalid_igmp_join == 'ttl':
           set_ttl = 10
           IGMPv3.fixup(pkt,invalid_ttl = set_ttl)
        else:
           IGMPv3.fixup(pkt)
        sendp(pkt, iface=iface)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_join_recvQuery(self, groups, rec_queryCount = None, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
        self.onos_ssm_table_load(groups, src_list)
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=g)
              gr.sources = src_list
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        if rec_queryCount == None:
            log.info('Sending IGMP join for group %s and waiting for one query packet and printing the packet' %groups)
            resp = srp1(pkt, iface=iface)
        else:
            log.info('Sending IGMP join for group %s and waiting for periodic query packets and printing one packet' %groups)
            resp = srp1(pkt, iface=iface)
#       resp = srp1(pkt, iface=iface) if rec_queryCount else srp3(pkt, iface=iface)
        resp[0].summary()
        log.info('Sent IGMP join for group %s and received a query packet and  printing packet' %groups)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
	log.info('entering into igmp leave function')
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface = iface)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave_listening_group_specific_query(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        log.info('Sending IGMP leave for group %s and waiting for one group specific query packet and printing the packet' %groups)
        resp = srp1(pkt, iface=iface)
        resp[0].summary()
        log.info('Sent IGMP leave for group %s and received a group specific query packet and printing packet' %groups)
        if delay != 0:
            time.sleep(delay)

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+390)
    def test_netCondition_with_delay_between_igmp_join_and_data_recv(self):
        self.setUp_igmp()
        randomDelay = randint(10,300)
        groups = ['224.0.1.1', '225.0.0.1']
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb, arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def mcast_traffic_delay_start():
            mcastTraffic.start()

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                result = self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_join(stateList)
                self.df.callback(0)

        self.send_igmp_join(groups)
        log.info('Holding multicast data for a period of random delay = {} secs'.format(randomDelay))
        t = Timer(randomDelay, mcast_traffic_delay_start)
        t.start()

        self.test_timer = reactor.callLater(randomDelay+30, self.mcast_traffic_timer)
        reactor.callLater(randomDelay+10, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+390)
    def test_netCondition_with_delay_between_data_recv_and_igmp_join(self):
        self.setUp_igmp()
        randomDelay = randint(10,300)
        groups = ['224.0.1.1', '225.0.0.1']
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb, arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def mcast_join_delay_start():
            log.info('Holding channel join for a period of random delay = {} secs'.format(randomDelay))
            self.send_igmp_join(groups)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                result = self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_join(stateList)
                self.df.callback(0)

        mcastTraffic.start()
        t = Timer(randomDelay, mcast_join_delay_start)
        t.start()

        self.test_timer = reactor.callLater(randomDelay+30, self.mcast_traffic_timer)
        reactor.callLater(randomDelay+10, igmp_srp_task, igmpStateList)
        return df


    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+340)
    def test_netCondition_with_delay_between_igmp_leave_and_data(self):
        self.setUp_igmp()
        randomDelay = randint(10,300)
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def mcast_leave_delay_start():
	    self.send_igmp_leave(leave_groups, delay = 3)
	    join_state = IGMPTestState(groups = leave_groups)
	    status = self.igmp_not_recv_task(self.V_INF1,leave_groups, join_state)
	    log.info('Verified status for igmp recv task %s'%status)
	    assert status == 1 , 'EXPECTED RESULT'
	    self.df.callback(0)

	mcastTraffic.start()
	self.send_igmp_join(groups)
        log.info('Holding multicast leave packet for a period of random delay = {} secs'.format(randomDelay))
        t = Timer(randomDelay+10, mcast_leave_delay_start)
        t.start()
        return df

    def igmp_not_recv_task(self, intf, groups, join_state):
	  log.info('Entering igmp not recv task loop')
          recv_socket = L2Socket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log.info('Verifying join interface should not receive any multicast data')
          self.NEGATIVE_TRAFFIC_STATUS = 1
          def igmp_recv_cb(pkt):
                log.info('Multicast packet %s received for left groups %s' %(pkt[IP].dst, groups))
                self.NEGATIVE_TRAFFIC_STATUS = 2
          sniff(prn = igmp_recv_cb, count = 1, lfilter = lambda p: IP in p and p[IP].dst in groups,
                timeout = 3, opened_socket = recv_socket)
          recv_socket.close()
          return self.NEGATIVE_TRAFFIC_STATUS

    ## Its sample test case based on this test case we had added all below scenarios.
    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_delay_between_positive_IdReq_and_tlsHelloReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        tls = TLSAuthTest()
        def eap_tls_eapTlsHelloReq_pkt_delay():
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_verify(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            log.info('Holding tlsHelloReq packet for a period of random delay = {} secs'.format(randomDelay))
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_delay_between_IdReq_and_tlsHelloReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        tls = TLSAuthTest()
        def eap_tls_eapTlsHelloReq_pkt_delay():
            log.info('Holding tlsHelloReq packet for a period of random delay = {} secs'.format(randomDelay))
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_verify(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+100)
    def test_netCondition_in_eap_tls_with_delay_between_tlsHelloReq_and_eapTlsCertReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        tls = TLSAuthTest()
        def eap_tls_eapTlsCertReq_pkt_delay():
            log.info('Holding eapTlsCertReq packet for a period of random delay = {} secs'.format(randomDelay))
            tls._eapTlsCertReq_delay()
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_verify(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            while tls.server_hello_done_received == False:
               r = tls.eapol_scapy_recv(cb = tls.eapol_server_hello_cb,
                                      lfilter =
                                      lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and \
                                          pkt[EAP].code == EAP.REQUEST)
               if len(r) == 0:
                  tls.tlsFail()
            t = Timer(randomDelay, eap_tls_eapTlsCertReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_delay_between_TlsCertReq_and_TlsChangeCipherSpec(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        tls = TLSAuthTest()
        def eap_tls_TlsChangeCipherSpec_pkt_delay():
            log.info('Holding TlsChangeCipherSpec packet for a period of random delay = {} secs'.format(randomDelay))
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_verify(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            t = Timer(randomDelay, eap_tls_TlsChangeCipherSpec_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_no_cert_and_delay_between_IdReq_and_HelloReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_no_cert_cb():
            log.info('TLS authentication failed with no certificate')
        tls = TLSAuthTest(fail_cb = tls_no_cert_cb, client_cert = '')
        def eap_tls_eapTlsHelloReq_pkt_delay():
            log.info('Holding HelloReq packet with no cert for a period of random delay = {} secs'.format(randomDelay))
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            assert_equal(tls.failTest, True)
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_no_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_no_cert, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+100)
    def test_netCondition_in_eap_tls_with_delay_and_no_cert_between_tlsHelloReq_and_eapTlsCertReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_no_cert_cb():
            log.info('TLS authentication failed with no certificate')
        tls = TLSAuthTest(fail_cb = tls_no_cert_cb, client_cert = '')
        def eap_tls_eapTlsHelloReq_pkt_delay():
            log.info('Holding eapTlsCertReq packet with no cert for a period of random delay = {} secs'.format(randomDelay))
            tls._eapTlsCertReq_delay()
            assert_equal(tls.failTest, True)
            tls._eapTlsChangeCipherSpec()
            assert_equal(tls.failTest, True)
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_no_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            while tls.server_hello_done_received == False:
               r = tls.eapol_scapy_recv(cb = tls.eapol_server_hello_cb,
                                      lfilter =
                                      lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and \
                                          pkt[EAP].code == EAP.REQUEST)
               if len(r) == 0:
                  tls.tlsFail()
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_no_cert, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_delay_and_no_cert_between_TlsCertReq_and_TlsChangeCipherSpec(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_no_cert_cb():
            log.info('TLS authentication failed with no certificate')
        tls = TLSAuthTest(fail_cb = tls_no_cert_cb, client_cert = '')
        def eap_tls_TlsChangeCipherSpec_pkt_delay():
            tls._eapTlsChangeCipherSpec()
            assert_equal(tls.failTest, True)
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_no_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            log.info('Holding TlsChangeCipherSpec packet with no cert for a period of random delay = {} secs'.format(randomDelay))
            t = Timer(randomDelay, eap_tls_TlsChangeCipherSpec_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_no_cert, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_IdReq_and_HelloReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_invalid_cert_cb():
            log.info('TLS authentication failed with invalid certificate')
        tls = TLSAuthTest(fail_cb = tls_invalid_cert_cb, client_cert = self.CLIENT_CERT_INVALID)
        def eap_tls_eapTlsHelloReq_pkt_delay():
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            assert_equal(tls.failTest, True)
            tls._eapTlsChangeCipherSpec()
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_invalid_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            log.info('Holding HelloReq packet with invalid cert for a period of random delay = {} secs'.format(randomDelay))
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_invalid_cert, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+100)
    def test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_tlsHelloReq_and_eapTlsCertReq(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_invalid_cert_cb():
            log.info('TLS authentication failed with invalid certificate')
        tls = TLSAuthTest(fail_cb = tls_invalid_cert_cb, client_cert = self.CLIENT_CERT_INVALID)
        def eap_tls_eapTlsHelloReq_pkt_delay():
            log.info('Holding eapTlsCertReq packet with invalid cert for a period of random delay = {} sec, delay'.format(randomDelay))
            tls._eapTlsCertReq_delay()
            tls._eapTlsChangeCipherSpec()
            assert_equal(tls.failTest, True)
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_invalid_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            while tls.server_hello_done_received == False:
               r = tls.eapol_scapy_recv(cb = tls.eapol_server_hello_cb,
                                      lfilter =
                                      lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and \
                                          pkt[EAP].code == EAP.REQUEST)
               if len(r) == 0:
                  tls.tlsFail()

            log.info('Holding eapTlsCertReq packet with invalid cert for a period of random delay = {} secs'.format(randomDelay))
            t = Timer(randomDelay, eap_tls_eapTlsHelloReq_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_invalid_cert, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_eap_tls_with_invalid_cert_delay_between_TlsCertReq_and_TlsChangeCipherSpec(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        def tls_invalid_cert_cb():
            log.info('TLS authentication failed with invalid certificate')
        tls = TLSAuthTest(fail_cb = tls_invalid_cert_cb, client_cert = self.CLIENT_CERT_INVALID)
        def eap_tls_TlsChangeCipherSpec_pkt_delay():
            tls._eapTlsChangeCipherSpec()
            assert_equal(tls.failTest, True)
            tls._eapTlsFinished()
            df.callback(0)
        def eap_tls_invalid_cert(df):
            tls._eapSetup()
            tls.tlsEventTable.EVT_EAP_SETUP
            tls._eapStart()
            tls.tlsEventTable.EVT_EAP_START
            tls._eapIdReq()
            tls.tlsEventTable.EVT_EAP_ID_REQ
            tls._eapTlsHelloReq()
            tls._eapTlsCertReq()
            log.info('Holding TlsChangeCipherSpec packet with invalid cert for a period of random delay = {} secs'.format(randomDelay))
            t = Timer(randomDelay, eap_tls_TlsChangeCipherSpec_pkt_delay)
            t.start()
        reactor.callLater(0, eap_tls_invalid_cert, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_in_multiple_eap_tls_requests_with_delay_between_IdReq_and_HelloReq(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 10
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                log.info('Holding tlsHelloReq packet for a period of random delay = {} secs'.format(randomDelay))
                time.sleep(randomDelay)
                tls._eapTlsHelloReq()
                tls._eapTlsCertReq()
                tls._eapTlsChangeCipherSpec()
                tls._eapTlsFinished()
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+450)
    def test_netCondition_with_multiple_authentication_and_delay_between_complete_authentication(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 100
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                tls._eapTlsHelloReq()
                tls._eapTlsCertReq()
                tls._eapTlsChangeCipherSpec()
                tls._eapTlsFinished()
                log.info('Authentication successful for user %d'%i)
           # Client authendicating multiple times one after other and making random delay in between authendication.
           for i in xrange(clients):
#            thread = threading.Thread(target = multiple_tls_random_delay)
             multiple_tls_random_delay()
             time.sleep(randomDelay)
           df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+450)
    def test_netCondition_with_multiple_authentication_and_delay_between_every_100_tls_burst(self):
        self.setUp_tls()
        randomDelay = randint(10,300)
        df = defer.Deferred()
        threads = []
        tls = []
        clients = 10
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                #randomDelay = 3
                for x in xrange(clients):
                   tls.append(TLSAuthTest(src_mac = 'random'))
                for x in xrange(clients):
                   tls[x]._eapSetup()
                   tls[x].tlsEventTable.EVT_EAP_SETUP
                for x in xrange(clients):
                   tls[x]._eapStart()
                   tls[x].tlsEventTable.EVT_EAP_START
                for x in xrange(clients):
                   tls[x]._eapIdReq()
                   tls[x].tlsEventTable.EVT_EAP_ID_REQ
                for x in xrange(clients):
                   tls[x]._eapTlsHelloReq()
                for x in xrange(clients):
                   tls[x]._eapTlsCertReq()
                for x in xrange(clients):
                   tls[x]._eapTlsChangeCipherSpec()
                for x in xrange(clients):
                   tls[x]._eapTlsFinished()
                for x in xrange(clients):
                   log.info('Authentication successful for user %d'%i)
           # Client authendicating multiple times one after other and making random delay in between authendication.
           for i in xrange(2):
             multiple_tls_random_delay()
             time.sleep(randomDelay)
           df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+90)
    def test_netCondition_with_delay_between_mac_flow_and_traffic(self):
        df = defer.Deferred()
        randomDelay = randint(10,300)
        #self.setUpClass_flows()
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:00:01'
        ingress_mac = '00:00:00:00:00:02'
        pkt = Ether(src = ingress_mac, dst = egress_mac)/IP()
        self.success = False

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src, pkt.dst))
                self.success = True
            sniff(count=2, timeout=randomDelay+50, lfilter = lambda p: p.src == ingress_mac,
                  prn = recv_cb, iface = self.port_map[egress])

        thread = threading.Thread(target = mac_recv_task)

        def send_flow_pkt_delay():
            sendp(pkt, count=50, iface = self.port_map[ingress])
            thread.join()
            assert_equal(self.success, True)
            df.callback(0)

        def creating_mac_flow(df):

            flow = OnosFlowCtrl(deviceId = self.device_id,
                               egressPort = egress,
                               ingressPort = ingress,
                               ethSrc = ingress_mac,
                               ethDst = egress_mac)
            result = flow.addFlow()
            assert_equal(result, True)
            ##wait for flows to be added to ONOS
            time.sleep(1)
            thread.start()
            log.info('Holding a packet to verify if flows are  active after {} secs'.format(randomDelay))
            t = Timer(randomDelay, send_flow_pkt_delay)
            t.start()
        reactor.callLater(0, creating_mac_flow, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY+90)
    def test_netCondition_with_delay_between_ip_flow_and_traffic(self):
        df = defer.Deferred()
        randomDelay = randint(10,300)
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        pkt = L2/L3

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout= randomDelay + 30,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip'],
                  prn = recv_cb, iface = self.port_map[egress])

        thread = threading.Thread(target = mac_recv_task)

        def send_flow_ip_pkt_delay():
            sendp(pkt, count=50, iface = self.port_map[ingress])
            thread.join()
            assert_equal(self.success, True)
            df.callback(0)

        def creating_ip_flow(df):
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
            ##wait for flows to be added to ONOS
            time.sleep(1)
            thread.start()
            log.info('Holding a packet to verify if flows are  active after {} secs'.format(randomDelay))
            t = Timer(randomDelay, send_flow_ip_pkt_delay)
            t.start()
        reactor.callLater(0, creating_ip_flow, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+90)
    def test_netCondition_with_delay_between_tcp_port_flow_and_traffic(self):
        df = defer.Deferred()
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': 9500 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': 9000 }
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = TCP(sport = ingress_map['tcp_port'], dport = egress_map['tcp_port'])
        pkt = L2/L3/L4

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                self.success = True
            sniff(count=2, timeout= randomDelay+30, lfilter = lambda p: TCP in p and p[TCP].dport == egress_map['tcp_port']
                        and p[TCP].sport == ingress_map['tcp_port'], prn = recv_cb, iface = self.port_map[egress])

        thread = threading.Thread(target = mac_recv_task)

        def send_flow_tcp_pkt_delay():
            sendp(pkt, count=50, iface = self.port_map[ingress])
            thread.join()
            assert_equal(self.success, True)
        #    df.callback(0)

        def creating_tcp_flow(df):
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
            thread.start()
            log.info('Holding a packet to verify if flows are active after {} sec, delay'.format(randomDelay))
            t = Timer(randomDelay, send_flow_tcp_pkt_delay)
            t.start()
        df.callback(0)
        reactor.callLater(0, creating_tcp_flow, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+90)
    def test_netCondition_with_delay_between_udp_port_flow_and_traffic(self):
        df = defer.Deferred()
        randomDelay = randint(10,300)
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': 9500 }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': 9000 }
        L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
        L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
        L4 = UDP(sport = ingress_map['udp_port'], dport = egress_map['udp_port'])
        pkt = L2/L3/L4

        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(count=2, timeout=randomDelay + 30,
             lfilter = lambda p: UDP in p and p[UDP].dport == egress_map['udp_port']
                                and p[UDP].sport == ingress_map['udp_port'], prn = recv_cb, iface = self.port_map[egress])

        thread = threading.Thread(target = mac_recv_task)

        def send_flow_udp_pkt_delay():
            sendp(pkt, count=50, iface = self.port_map[ingress])
            thread.join()
            assert_equal(self.success, True)
            df.callback(0)

        def creating_udp_flow(df):
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
            thread.start()
            log.info('Holding a packet to verify if flows are active after {} secs'.format(randomDelay))
            t = Timer(randomDelay, send_flow_udp_pkt_delay)
            t.start()

        df.callback(0)
        reactor.callLater(0, creating_udp_flow, df)
        return df

    def netCondition_with_delay_between_multiple_igmp_joins_and_data(self,users,group_end_ip,source_list_end_ip,user_src_end_ip, data_pkt =50):
        self.setUp_igmp()
        randomDelay = []
        groups = []
        sources = []
        subscribers_src_ip = []
        status = []
        join_threads = []
        delay_threads = []
        data_threads = []
        threads = []
        subscriber = users
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '229.0.0.1',end_ip = group_end_ip)
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = source_list_end_ip)
        subscriber_sourceips = self.source_ip_range(start_ip = '20.20.0.1',end_ip = user_src_end_ip)
        while count<=subscriber:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            subscriber_sourceip = random.choice(subscriber_sourceips)
            if group in groups:
                pass
            else:
                log.info('group = %s source list = %s and subscriber source ip in join = %s'%(group,source, subscriber_sourceip))
                groups.append(group)
                sources.append(source)
                subscribers_src_ip.append(subscriber_sourceip)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)

        def multiple_joins_send_in_threads(group, source, subscriber_src_ip,data_pkt = data_pkt):
            self.send_igmp_join(groups = [group], src_list = [source],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1, ip_src = [subscriber_src_ip])
            randomDelay_in_thread = randint(10,30)
            log.info('This is running in a thread, with  igmp join sent and delay {}'.format(randomDelay_in_thread))
            time.sleep(randomDelay_in_thread)
            log.info('This is running in a thread, with igmp join sent and delay {}'.format(randomDelay_in_thread))
            status = self.verify_igmp_data_traffic_in_thread(group,intf=self.V_INF1,source=source, data_pkt = data_pkt)
            #assert_equal(status, True)
            log.info('Data received for group %s from source %s and status is %s '%(group,source,status))
            self.igmp_threads_result.append(status)

        for i in range(subscriber):
            thread = threading.Thread(target = multiple_joins_send_in_threads, args = (groups[i], sources[i], subscribers_src_ip[i]))
            time.sleep(randint(1,2))
            thread.start()
            threads.append(thread)

#        time.sleep(50)
        for thread in threads:
            thread.join()

    def verify_igmp_data_traffic_in_thread(self, group, intf='veth0', source='1.2.3.4', data_pkt =50, negative = None):
        log.info('Verifying multicast traffic for group %s from source %s'%(group,source))
        self.success = False
        def recv_task():
            def igmp_recv_cb(pkt):
                #log.info('received multicast data packet is %s'%pkt.show())
                log.info('Multicast data received for group %s from source %s'%(group,source))
                self.success = True
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].dst == group and p[IP].src == source, count=1,timeout = 2, iface='veth0')
        t = threading.Thread(target = recv_task)
        t.start()
        self.send_multicast_data_traffic_from_thread(group,source=source, data_pkt=data_pkt)
        t.join()
        if (negative is None) and self.success is True:
           return self.success
        elif (negative is not None) and self.success is True:
           log.info('Multicast traffic should not received because this is negative scenario, but it is received')
           self.success = False
        elif (negative is not None) and self.success is False:
           log.info('Multicast traffic should is not received because this is negative scenario, hence status is True')
           self.success = True
        return self.success

    def send_multicast_data_traffic_from_thread(self, group, intf= 'veth2',source = '1.2.3.4', data_pkt = 50):
        dst_mac = self.iptomac_convert(group)
        eth = Ether(dst= dst_mac)
        ip = IP(dst=group,src=source)
        data = repr(monotonic.monotonic())
        log.info('Sending %s number of multicast packet to the multicast group %s'%(data_pkt, group))
        sendp(eth/ip/data,count=data_pkt, iface = intf)
        pkt = (eth/ip/data)
        #log.info('multicast traffic packet %s'%pkt.show())

    def iptomac_convert(self, mcast_ip):
        mcast_mac =  '01:00:5e:'
        octets = mcast_ip.split('.')
        second_oct = int(octets[1]) & 127
        third_oct = int(octets[2])
        fourth_oct = int(octets[3])
        mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
        return mcast_mac

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_multiple_subscribers(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            no_users = 10
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_delay_between_multiple_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip,
                                                                          source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_multiple_subscribers_with_low_multicast_data_rate(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            no_users = 10
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_delay_between_multiple_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip,
                                             source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip, data_pkt = 20)
            log.info('IGMP Thread status after running igmp thread %s '%(self.igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_same_subscriber(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            no_users = 5
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.0.1'
            self.netCondition_with_delay_between_multiple_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip,
                                                                          source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_delay_between_same_igmp_joins_and_data_from_multiple_subscriber(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            no_users = 100
            group_end_ip = '229.0.0.1'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_delay_between_multiple_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip,
                                                                          source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_same_sourcelist_for_multiple_subscriber(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            no_users = 20
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.0.1'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_delay_between_multiple_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip,
                                                                          source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df


    def netCondition_with_multiple_scenarios_igmp_joins_and_data(self,users,group_end_ip,source_list_end_ip,user_src_end_ip,bunch_traffic, data_pkt =50,invalid_joins = None):
        self.setUp_igmp()
        randomDelay = []
        groups = []
        sources = []
        subscribers_src_ip = []
        status = []
        join_threads = []
        delay_threads = []
        data_threads = []
        threads = []
        subscriber = users
        count = 1
        j = 1
        negative_traffic = None
        mcastips = self.mcast_ip_range(start_ip = '229.0.0.1',end_ip = group_end_ip)
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = source_list_end_ip)
        subscriber_sourceips = self.source_ip_range(start_ip = '20.20.0.1',end_ip = user_src_end_ip)
        while count<=subscriber:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            subscriber_sourceip = random.choice(subscriber_sourceips)
            if group in groups:
                pass
            else:
                log.info('group = %s source list = %s and subscriber source ip in join = %s'%(group,source, subscriber_sourceip))
                groups.append(group)
                sources.append(source)
                subscribers_src_ip.append(subscriber_sourceip)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)

        def multiple_joins_send_in_threads(group, source, subscriber_src_ip,invalid_igmp_join,data_pkt = data_pkt):
            if invalid_igmp_join is None:
               self.send_igmp_join(groups = [group], src_list = [source],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1, ip_src = [subscriber_src_ip])
            else:
               negative_traffic = True
               self.send_igmp_join_negative(groups = [group], src_list = [source],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                           iface = self.V_INF1, ip_src = [subscriber_src_ip], invalid_igmp_join = invalid_igmp_join)
            randomDelay_in_thread = randint(10,30)
            log.info('This is running in thread with igmp join sent and delay {}'.format(randomDelay_in_thread))
            time.sleep(randomDelay_in_thread)
            log.info('This is running in thread with igmp join sent and delay {}'.format(randomDelay_in_thread))
            status = self.verify_igmp_data_traffic_in_thread(group,intf=self.V_INF1,source=source, data_pkt = data_pkt,negative=negative_traffic)
            #assert_equal(status, True)
            log.info('data received for group %s from source %s and status is %s '%(group,source,status))
            self.igmp_threads_result.append(status)

        for i in range(subscriber):
            thread = threading.Thread(target = multiple_joins_send_in_threads, args = (groups[i], sources[i], subscribers_src_ip[i], invalid_joins))
            if bunch_traffic ==  'yes':
               if j == 10:
                  log.info('Here we are throttle traffic for 100 sec of delay and agian creating igmp threads')
                  time.sleep(randint(100,110))
                  j = 1
               else:
                  j = j+ 1
            time.sleep(randint(1,2))
            thread.start()
            threads.append(thread)

#        time.sleep(250)
        for thread in threads:
            thread.join()


    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_throttle_between_multiple_igmp_joins_and_data_from_multiple_subscribers(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            batch_traffic_run = 'yes'
            no_users = 11
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_multiple_scenarios_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip, source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip, bunch_traffic = batch_traffic_run, data_pkt = 50 )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_invalid_igmp_type_and_multiple_igmp_joins_and_data_from_multiple_subscribers(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            batch_traffic_run = 'no'
            invalid_igmp_join = 'igmp_type'
            no_users = 11
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_multiple_scenarios_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip, source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip, bunch_traffic = batch_traffic_run, data_pkt = 50, invalid_joins = invalid_igmp_join )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_invalid_record_type_and_multiple_igmp_joins_and_data_from_multiple_subscribers(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            batch_traffic_run = 'no'
            invalid_igmp_join = 'record_type'
            no_users = 11
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_multiple_scenarios_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip, source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip, bunch_traffic = batch_traffic_run, data_pkt = 50, invalid_joins = invalid_igmp_join )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY+50)
    def test_netCondition_with_invalid_ttl_and_multiple_igmp_joins_and_data_from_multiple_subscribers(self):
        self.setUp_tls()
        df = defer.Deferred()
        log.info('IGMP Thread status before running igmp thread %s '%(self.igmp_threads_result))
        def netCondition_multiple_igmp_joins_and_data(df):
            ### Start ips of multicast, source list and subscriber source ip are '229.0.0.1', '10.10.0.1' and '20.20.0.1' respectively
            batch_traffic_run = 'no'
            invalid_igmp_join = 'ttl_type'
            no_users = 11
            group_end_ip = '229.0.30.254'
            source_list_end_ip = '10.10.30.254'
            subscriber_src_end_ip = '20.20.20.254'
            self.netCondition_with_multiple_scenarios_igmp_joins_and_data(users = no_users, group_end_ip = group_end_ip, source_list_end_ip = source_list_end_ip, user_src_end_ip = subscriber_src_end_ip, bunch_traffic = batch_traffic_run, data_pkt = 10, invalid_joins = invalid_igmp_join )
            log.info('IGMP Thread status after running igmp thread %s '%(self. igmp_threads_result))
            for i in xrange(no_users):
               log.info('IGMP Thread %s status is %s after running igmp thread '%(i,self.igmp_threads_result[i]))
               if assert_equal(self.igmp_threads_result[i], True) is True:
                  df.callback(0)
            df.callback(0)
        reactor.callLater(0, netCondition_multiple_igmp_joins_and_data, df)
        return df


    @deferred(TEST_TIMEOUT_DELAY-250)
    def test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_exchanges_between_serverHello_and_client_packet(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 1
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                tls._eapTlsCertReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsHelloReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsChangeCipherSpec()
                assert_equal(tls.failTest, True)
                tls._eapTlsFinished()
                assert_equal(tls.failTest, True)
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY-250)
    def test_netCondition_in_multiple_eap_tls_session_with_out_of_order_exchanges_in_eapTlsCertReq_packets(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 1
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapTlsCertReq()
                assert_equal(tls.failTest, True)
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                assert_equal(tls.failTest, True)
                tls._eapTlsCertReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsHelloReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsChangeCipherSpec()
                assert_equal(tls.failTest, True)
                tls._eapTlsFinished()
                assert_equal(tls.failTest, True)
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY-250)
    def test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_eapTlsChangeCipherSpec_packets(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 1
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapTlsChangeCipherSpec()
                tls.failTest = False
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                assert_equal(tls.failTest, True)
                tls._eapTlsHelloReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsCertReq()
                assert_equal(tls.failTest, True)
                tls._eapTlsChangeCipherSpec()
                assert_equal(tls.failTest, True)
                tls._eapTlsFinished()
                assert_equal(tls.failTest, True)
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY-250)
    def test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsHelloReq_packets(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 1
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                #tls._eapTlsHelloReq()
                tls._eapTlsCertReq()
                tls._eapTlsChangeCipherSpec()
                assert_equal(tls.failTest, True)
                tls._eapTlsFinished()
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

    @deferred(TEST_TIMEOUT_DELAY-250)
    def test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsChangeCipherSpec_packets(self):
        self.setUp_tls()
        df = defer.Deferred()
        threads = []
        clients = 1
        def eap_tls_eapTlsHelloReq_pkt_delay(df):
           def multiple_tls_random_delay():
                randomDelay = randint(10,300)
                tls = TLSAuthTest(src_mac = 'random')
                tls._eapSetup()
                tls.tlsEventTable.EVT_EAP_SETUP
                tls._eapStart()
                tls.tlsEventTable.EVT_EAP_START
                tls._eapIdReq()
                tls.tlsEventTable.EVT_EAP_ID_REQ
                tls._eapTlsHelloReq()
                tls._eapTlsCertReq()
                #tls._eapTlsChangeCipherSpec()
                assert_equal(tls.failTest, True)
                tls._eapTlsFinished()
                log.info('Authentication successful for user %d'%i)
           # Sending multiple tls clients and making random delay in between client and server packets.
           for i in xrange(clients):
             thread = threading.Thread(target = multiple_tls_random_delay)
             time.sleep(randint(1,2))
             thread.start()
             threads.append(thread)
           time.sleep(300)
           for thread in threads:
               thread.join()
               #df.callback(0)
        reactor.callLater(0, eap_tls_eapTlsHelloReq_pkt_delay, df)
        return df

