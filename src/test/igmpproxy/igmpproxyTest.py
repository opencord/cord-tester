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
from twisted.internet import defer
from nose.tools import *
from nose.twistedtools import reactor, deferred
from scapy.all import *
from select import select as socket_select
import time, monotonic
import os
import random
import threading
from IGMP import *
from McastTraffic import *
from Stats import Stats
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from Channels import IgmpChannel
from CordLogger import CordLogger
from CordTestConfig import setup_module, teardown_module
from CordTestUtils import log_test
log_test.setLevel('INFO')

class IGMPProxyTestState:

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

class igmpproxy_exchange(CordLogger):

    V_INF1 = 'veth0'
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
    MCAST_TRAFFIC_TIMEOUT = 20
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    app = 'org.opencord.igmpproxy'
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json'))
    ROVER_TEST_TIMEOUT = 300 #3600*86
    ROVER_TIMEOUT = (ROVER_TEST_TIMEOUT - 100)
    ROVER_JOIN_TIMEOUT = 60
    VOLTHA_ENABLED = bool(int(os.getenv('VOLTHA_ENABLED', 0)))

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, _ = cls.olt.olt_port_map()
        if cls.VOLTHA_ENABLED is False:
            OnosCtrl.config_device_driver()
            OnosCtrl.cord_olt_config(cls.olt)
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        if cls.VOLTHA_ENABLED is False:
            OnosCtrl.config_device_driver(driver = 'ovs')

    def setUp(self):
        ''' Activate the igmp proxy app'''
        super(igmp_exchange, self).setUp()
        self.onos_ctrl = OnosCtrl(self.app)
	self.onos_ctrl.activate()
        self.igmp_channel = IgmpChannel()

    def tearDown(self):
        super(igmp_exchange, self).tearDown()

    def onos_load_config(self, config):
	log_test.info('onos load config is %s'%config)
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    def onos_ssm_table_load(self, groups, src_list = ['1.2.3.4'],flag = False):
          return
          ssm_dict = {'apps' : { 'org.opencord.igmpproxy' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.opencord.igmpproxy']['ssmTranslate']
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
          self.onos_load_config(ssm_dict)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          self.igmp_channel.cord_port_table_load(cord_port_map)
          time.sleep(2)

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
            log_test.info('Receive stats %s for group %s' %(rx_stats, g))

        log_test.info('IGMP test verification success')

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
                log_test.info('Received %d packets for group %s' %(rx, g))
        for g in leave_groups:
            rx = recvState.group_map[g][1].count
            assert_equal(rx, 0)

        log_test.info('IGMP test verification success')

    def mcast_traffic_timer(self):
          log_test.info('MCAST traffic timer expiry')
          self.mcastTraffic.stopReceives()

    def send_mcast_cb(self, send_state):
        for g in send_state.groups:
            send_state.update(g, tx = 1)
        return 0

    ##Runs in the context of twisted reactor thread
    def igmp_recv(self, igmpState):
        s = socket_select([self.recv_socket], [], [], 1.0)
        if self.recv_socket in s[0]:
              p = self.recv_socket.recv()
              try:
                    send_time = float(p.payload.load)
                    recv_time = monotonic.monotonic()
              except:
                    log_test.info('Unexpected Payload received: %s' %p.payload.load)
                    return 0
              #log_test.info( 'Recv in %.6f secs' %(recv_time - send_time))
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
            log_test.info('Sending IGMP join for group %s and waiting for one query packet and printing the packet' %groups)
            resp = srp1(pkt, iface=iface)
        else:
            log_test.info('Sending IGMP join for group %s and waiting for periodic query packets and printing one packet' %groups)
            resp = srp1(pkt, iface=iface)
#       resp = srp1(pkt, iface=iface) if rec_queryCount else srp3(pkt, iface=iface)
        resp[0].summary()
        log_test.info('Sent IGMP join for group %s and received a query packet and  printing packet' %groups)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
	log_test.info('entering into igmp leave function')
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

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmpproxy_with_join_and_verify_traffic(self):
        groups = [self.MGROUP1, self.MGROUP1]
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPProxyTestState(groups = groups, df = df)
        igmpStateRecv = IGMPProxyTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        tx_intf = self.port_map[self.PORT_TX_DEFAULT]
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        mcastTraffic = McastTraffic(groups, iface= tx_intf, cb = self.send_mcast_cb, arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = rx_intf, type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                #log_test.info('Sending IGMP leave for groups: %s' %groups)
                self.send_igmp_leave(groups, iface = rx_intf, delay = 2)
                self.recv_socket.close()
                self.igmp_verify_join(stateList)
                self.df.callback(0)

        self.send_igmp_join(groups, iface = rx_intf)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+40)
    def test_igmpproxy_with_leave_and_verify_traffic(self):
        groups = [self.MGROUP1]
        leave_groups = [self.MGROUP1]
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPProxyTestState(groups = groups, df = df)
        IGMPProxyTestState(groups = groups, df = df)
        tx_intf = self.port_map[self.PORT_TX_DEFAULT]
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        mcastTraffic = McastTraffic(groups, iface= tx_intf, cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = rx_intf, type = ETH_P_IP)

	mcastTraffic.start()
	self.send_igmp_join(groups, iface = rx_intf)
        time.sleep(5)
	self.send_igmp_leave(leave_groups, delay = 3, iface = rx_intf)
        time.sleep(10)
	join_state = IGMPProxyTestState(groups = leave_groups)
	status = self.igmp_not_recv_task(rx_intf, leave_groups, join_state)
	log_test.info('verified status for igmp recv task %s'%status)
	assert status == 1 , 'EXPECTED RESULT'
	self.df.callback(0)
        return df

    @deferred(timeout=100)
    def test_igmpproxy_with_leave_and_join_loop(self):
        self.groups = ['226.0.1.1', '227.0.0.1', '228.0.0.1', '229.0.0.1', '230.0.0.1' ]
        self.src_list = ['3.4.5.6', '7.8.9.10']
	self.onos_ssm_table_load(self.groups,src_list=self.src_list)
        df = defer.Deferred()
        self.df = df
        self.iterations = 0
        self.num_groups = len(self.groups)
        self.MAX_TEST_ITERATIONS = 10
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]

        def igmp_srp_task(v):
              if self.iterations < self.MAX_TEST_ITERATIONS:
                    if v == 1:
                          ##join test
                          self.num_groups = random.randint(0, len(self.groups))
                          self.send_igmp_join(self.groups[:self.num_groups],
                                              src_list = self.src_list,
                                              iface = rx_intf, delay = 0)
                    else:
                          self.send_igmp_leave(self.groups[:self.num_groups],
                                               src_list = self.src_list,
                                               iface = rx_intf, delay = 0)
                    self.iterations += 1
                    v ^= 1
                    reactor.callLater(1.0 + 0.5*self.num_groups,
                                      igmp_srp_task, v)
              else:
                    self.df.callback(0)

        reactor.callLater(0, igmp_srp_task, 1)
        return df

    def igmp_join_task(self, intf, groups, state, src_list = ['1.2.3.4']):
          #self.onos_ssm_table_load(groups, src_list)
          igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                        gaddr=self.IP_DST)
          for g in groups:
                gr = IGMPv3gr(rtype = IGMP_V3_GR_TYPE_INCLUDE, mcaddr = g)
                gr.sources = src_list
                igmp.grps.append(gr)

          for g in groups:
                state.group_map[g][0].update(1, t = monotonic.monotonic())

          pkt = self.igmp_eth/self.igmp_ip/igmp
          IGMPv3.fixup(pkt)
          sendp(pkt, iface=intf)
          log_test.debug('Returning from join task')

    def igmp_recv_task(self, intf, groups, join_state):
          recv_socket = L3PacketSocket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log_test.info('Verifying join interface should receive multicast data')
          while True:
                p = recv_socket.recv()
                if p.dst in groups and group_map[p.dst][0] == 0:
                      group_map[p.dst][0] += 1
                      group_map[p.dst][1] = monotonic.monotonic()
                      c = 0
                      for g in groups:
                            c += group_map[g][0]
                      if c == len(groups):
                            break
          for g in groups:
                join_start = join_state.group_map[g][0].start
                recv_time = group_map[g][1] * 1000000
                delta = (recv_time - join_start)
                log_test.info('Join for group %s received in %.3f usecs' %
                         (g, delta))

          recv_socket.close()
          log_test.debug('Returning from recv task')

    def igmp_not_recv_task(self, intf, groups, join_state):
	  log_test.info('Entering igmp not recv task loop')
          recv_socket = L2Socket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log_test.info('Verifying join interface, should not receive any multicast data')
          self.NEGATIVE_TRAFFIC_STATUS = 1
          def igmp_recv_cb(pkt):
                log_test.info('Multicast packet %s received for left groups %s' %(pkt[IP].dst, groups))
                self.NEGATIVE_TRAFFIC_STATUS = 2
          sniff(prn = igmp_recv_cb, count = 1, lfilter = lambda p: IP in p and p[IP].dst in groups,
                timeout = 3, opened_socket = recv_socket)
          recv_socket.close()
          return self.NEGATIVE_TRAFFIC_STATUS

    def group_latency_check(self, groups):
          tasks = []
          self.send_igmp_leave(groups = groups)
          join_state = IGMPProxyTestState(groups = groups)
          tasks.append(threading.Thread(target=self.igmp_join_task, args = ('veth0', groups, join_state,)))
          traffic_state = IGMPProxyTestState(groups = groups)
          mcast_traffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                       arg = traffic_state)
          mcast_traffic.start()
          tasks.append(threading.Thread(target=self.igmp_recv_task, args = ('veth0', groups, join_state)))
          for t in tasks:
                t.start()
          for t in tasks:
                t.join()

          mcast_traffic.stop()
          self.send_igmp_leave(groups = groups)
          return

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_1group_join_latency(self):
        groups = ['239.0.1.1']
        df = defer.Deferred()
        def igmp_1group_join_latency():
              self.group_latency_check(groups)
              df.callback(0)
        reactor.callLater(0, igmp_1group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_2group_join_latency(self):
        groups = [self.MGROUP1, self.MGROUP1]
        df = defer.Deferred()
        def igmp_2group_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_2group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_Ngroup_join_latency(self):
        groups = ['239.0.1.1', '240.0.1.1', '241.0.1.1', '242.0.1.1']
        df = defer.Deferred()
        def igmp_Ngroup_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_Ngroup_join_latency)
        return df

    def test_igmpproxy_with_join_rover_all(self):
          s = (224 << 24) | 1
          #e = (225 << 24) | (255 << 16) | (255 << 16) | 255
          e = (224 << 24) | 10
          for i in xrange(s, e+1):
                if i&0xff:
                      ip = '%d.%d.%d.%d'%((i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
                self.send_igmp_join([ip], delay = 0)

    @deferred(timeout=ROVER_TEST_TIMEOUT)
    def test_igmpproxy_with_join_rover(self):
          df = defer.Deferred()
          iface = self.get_igmp_intf()
          self.df = df
          self.count = 0
          self.timeout = 0
          self.complete = False
          def igmp_join_timer():
                self.timeout += self.ROVER_JOIN_TIMEOUT
                log_test.info('IGMP joins sent: %d' %self.count)
                if self.timeout >= self.ROVER_TIMEOUT:
                      self.complete = True
                reactor.callLater(self.ROVER_JOIN_TIMEOUT, igmp_join_timer)

          reactor.callLater(self.ROVER_JOIN_TIMEOUT, igmp_join_timer)
          self.start_channel = (224 << 24) | 1
          self.end_channel = (224 << 24) | 200 #(225 << 24) | (255 << 16) | (255 << 16) | 255
          self.current_channel = self.start_channel
          def igmp_join_rover(self):
                #e = (224 << 24) | 10
                chan = self.current_channel
                self.current_channel += 1
                if self.current_channel >= self.end_channel:
                      chan = self.current_channel = self.start_channel
                if chan&0xff:
                      ip = '%d.%d.%d.%d'%((chan>>24)&0xff, (chan>>16)&0xff, (chan>>8)&0xff, chan&0xff)
                      self.send_igmp_join([ip], delay = 0, ssm_load = False, iface = iface)
                      self.count += 1
                if self.complete == True:
                      log_test.info('%d IGMP joins sent in %d seconds over %s' %(self.count, self.timeout, iface))
                      self.df.callback(0)
                else:
                      reactor.callLater(0, igmp_join_rover, self)
          reactor.callLater(0, igmp_join_rover, self)
          return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_query(self):
        groups = ['224.0.0.1'] ##igmp query group
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        self.df = df
        self.recv_socket = L2Socket(iface = 'veth0', type = ETH_P_IP)

        def igmp_query_timeout():
              def igmp_query_cb(pkt):
		    log_test.info('received igmp query packet is %s'%pkt.show())
                    log_test.info('Got IGMP query packet from %s for %s' %(pkt[IP].src, pkt[IP].dst))
                    assert_equal(pkt[IP].dst, '224.0.0.1')
              sniff(prn = igmp_query_cb, count=1, lfilter = lambda p: IP in p and p[IP].dst in groups,
                    opened_socket = self.recv_socket)
              self.recv_socket.close()
              self.df.callback(0)

        #self.send_igmp_join(groups)
        self.test_timer = reactor.callLater(self.IGMP_QUERY_TIMEOUT, igmp_query_timeout)
        return df
