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
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from scapy.all import *
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

class igmp_exchange(CordLogger):

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
    MCAST_TRAFFIC_TIMEOUT = 10
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    app = 'org.opencord.igmp'
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json'))
    ROVER_TEST_TIMEOUT = 300 #3600*86
    ROVER_TIMEOUT = (ROVER_TEST_TIMEOUT - 100)
    ROVER_JOIN_TIMEOUT = 60

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, _ = cls.olt.olt_port_map()
        OnosCtrl.config_device_driver()
        OnosCtrl.cord_olt_config(cls.olt)
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        OnosCtrl.config_device_driver(driver = 'ovs')

    def setUp(self):
        ''' Activate the igmp app'''
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
          ssm_dict = {'apps' : { 'org.opencord.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.opencord.igmp']['ssmTranslate']
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
        log_test.info('Sending IGMP leave for group %s and waiting for one group specific query packet and printing the packet' %groups)
        resp = srp1(pkt, iface=iface)
        resp[0].summary()
        log_test.info('Sent IGMP leave for group %s and received a group specific query packet and printing packet' %groups)
        if delay != 0:
            time.sleep(delay)

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_join_verify_traffic(self):
        groups = [self.MGROUP1, self.MGROUP1]
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
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
                self.recv_socket.close()
                self.igmp_verify_join(stateList)
                self.df.callback(0)

        self.send_igmp_join(groups, iface = rx_intf)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+40)
    def test_igmp_leave_verify_traffic(self):
        groups = [self.MGROUP1]
        leave_groups = [self.MGROUP1]
	self.onos_ssm_table_load(groups)
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        IGMPTestState(groups = groups, df = df)
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
	join_state = IGMPTestState(groups = leave_groups)
	status = self.igmp_not_recv_task(rx_intf, leave_groups, join_state)
	log_test.info('verified status for igmp recv task %s'%status)
	assert status == 1 , 'EXPECTED RESULT'
	self.df.callback(0)
        return df

    @deferred(timeout=100)
    def test_igmp_leave_join_loop(self):
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
          join_state = IGMPTestState(groups = groups)
          tasks.append(threading.Thread(target=self.igmp_join_task, args = ('veth0', groups, join_state,)))
          traffic_state = IGMPTestState(groups = groups)
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
    def test_igmp_1group_join_latency(self):
        groups = ['239.0.1.1']
        df = defer.Deferred()
        def igmp_1group_join_latency():
              self.group_latency_check(groups)
              df.callback(0)
        reactor.callLater(0, igmp_1group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmp_2group_join_latency(self):
        groups = [self.MGROUP1, self.MGROUP1]
        df = defer.Deferred()
        def igmp_2group_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_2group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmp_Ngroup_join_latency(self):
        groups = ['239.0.1.1', '240.0.1.1', '241.0.1.1', '242.0.1.1']
        df = defer.Deferred()
        def igmp_Ngroup_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_Ngroup_join_latency)
        return df

    def test_igmp_join_rover_all(self):
          s = (224 << 24) | 1
          #e = (225 << 24) | (255 << 16) | (255 << 16) | 255
          e = (224 << 24) | 10
          for i in xrange(s, e+1):
                if i&0xff:
                      ip = '%d.%d.%d.%d'%((i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
                self.send_igmp_join([ip], delay = 0)

    @deferred(timeout=ROVER_TEST_TIMEOUT)
    def test_igmp_join_rover(self):
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
    def test_igmp_query(self):
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

    def igmp_send_joins_different_groups_srclist(self, groups, sources, intf = V_INF1, delay = 2, ip_src = None):
        g1 = groups[0]
        g2 = groups[1]
        sourcelist1 = sources[0]
        sourcelist2 = sources[1]
        eth = Ether(dst = self.IGMP_DST_MAC,type = ETH_P_IP)
        ip = IP(dst = self.IP_DST)
        log_test.info('Sending join message for the group %s' %g1)
        self.send_igmp_join((g1,), src_list = sourcelist1, ip_pkt = eth/ip, iface = intf, delay = 2)
        eth = Ether(dst = self.MMACGROUP2, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
        ip = IP(dst = g2)
        log_test.info('Sending join message for group %s' %g2)
        self.send_igmp_join((g2,), src_list = sourcelist2, ip_pkt = eth/ip, iface = intf, delay = 2)
        log_test.info('Done with igmp_send_joins_different_groups_srclist')

    def igmp_send_joins_different_groups_srclist_wait_query_packets(self, groups, sources, intf = V_INF1, delay = 2, ip_src = None, query_group1 = None, query_group2 = None):
        g1 = groups[0]
        g2 = groups[1]
        sourcelist1 = sources[0]
        sourcelist2 = sources[1]
        eth = Ether(dst = self.MMACGROUP1, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
        src_ip = ip_src or self.IP_SRC
        ip = IP(dst = g1, src = src_ip)
        if query_group1 is 'group1':
            log_test.info('Sending join message for the group %s and waiting for a query packet on join interface' %g1)
            self.send_igmp_join_recvQuery((g1,), None, src_list = sourcelist1, ip_pkt = eth/ip, iface = intf, delay = 2)
        else:
            log_test.info('Sending join message for the group %s' %g1)
            self.send_igmp_join((g1,), src_list = sourcelist1, ip_pkt = eth/ip, iface = intf, delay = 2)
        eth = Ether(dst = self.MMACGROUP2, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
        ip = IP(dst = g2, src = src_ip)
        if query_group2 is 'group2':
            log_test.info('Sending join message for the group %s and waiting for a query packet on join interface' %g2)
            self.send_igmp_join_recvQuery((g2,), None, src_list = sourcelist2, ip_pkt = eth/ip, iface = intf, delay = 2)
        else:
            log_test.info('Sending join message for group %s' %g2)
            self.send_igmp_join((g2,), src_list = sourcelist2, ip_pkt = eth/ip, iface = intf, delay = 2)

    def igmp_joins_leave(self,groups,src_list,again_join = False, df = None):
        groups1 = [groups[0]]
        groups2 = [groups[1]]
	src1 = [src_list[0]]
	src2 = [src_list[1]]
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (src1, src2), intf = self.V_INF1, delay = 2)

        src_ip = src1[0]
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)

        igmpState2 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
	dst_mac = self.iptomac(groups1[0])
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb,
                                     arg = igmpState1)
        src_ip = src2[0]
	dst_mac = self.iptomac(groups1[0])
        mcastTraffic2 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb,
                                     arg = igmpState2)
        mcastTraffic1.start()
        mcastTraffic2.start()
        join_state1 = IGMPTestState(groups = groups1)
        join_state2 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log_test.info('Interface is receiving multicast groups %s' %groups1)
        self.igmp_recv_task(self.V_INF1, groups2, join_state2)
        log_test.info('Interface is receiving multicast groups %s' %groups2)
        log_test.info('Interface is sending leave message for groups %s now' %groups2)
        self.send_igmp_leave(groups = groups2, src_list = src2, iface = self.V_INF1, delay = 2)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        target4 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state2)
        assert target4 == 1, 'EXPECTED FAILURE'
        if again_join:
            dst_mac = '01:00:5e:02:02:03'
            ip_dst = '239.2.2.3'
            eth = Ether(dst = dst_mac,  type = ETH_P_IP)
            ip = IP(dst = ip_dst)
            log_test.info('Interface sending join message again for the groups %s' %groups2)
            self.send_igmp_join(groups2, src_list = [src_ip], ip_pkt = eth/ip, iface = self.V_INF1, delay = 2)
            self.igmp_recv_task(self.V_INF1, groups2, join_state2)
            log_test.info('Interface is receiving multicast groups %s again' %groups2)
            self.igmp_recv_task(self.V_INF1, groups1, join_state1)
            log_test.info('Interface is still receiving from multicast groups %s' %groups1)
        else:
            log_test.info('Ended test case')
        mcastTraffic1.stop()
        mcastTraffic2.stop()


    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_2joins_1leave(self):
        df = defer.Deferred()
        def igmp_2joins_1leave():
	      groups = ['234.2.3.4','236.8.7.9']
	      src_list = ['2.3.4.5','5.4.3.2']
	      self.onos_ssm_table_load(groups,src_list = src_list)
              self.igmp_joins_leave(groups,src_list,again_join = False, df = df)
              df.callback(0)
        reactor.callLater(0, igmp_2joins_1leave)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+25)
    def test_igmp_2joins_1leave_and_join_again(self):
        df = defer.Deferred()
        def igmp_2joins_1leave_join_again():
	      groups = ['234.2.3.4','236.8.7.9']
	      src_list = ['2.3.4.5','5.4.3.2']
	      self.onos_ssm_table_load(groups,src_list = src_list)
              self.igmp_joins_leave(groups,src_list,again_join = True, df = df)
              df.callback(0)
        reactor.callLater(0, igmp_2joins_1leave_join_again)
        return df

    def igmp_not_in_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
	self.onos_ssm_table_load(groups1 + groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','2.2.2.2', '5.5.5.5'])
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                     (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        src_ip = '6.6.6.6'
	dst_mac = self.iptomac(groups1[0])
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface = 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        log_test.info('Interface should not receive from multicast groups %s from an interface, which is expected' %groups1)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 2, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s, working as expected' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_not_in_src_list(self):
        df = defer.Deferred()
        def igmp_not_in_src_list():
              self.igmp_not_in_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_not_in_src_list)
        return df

    def igmp_change_to_exclude_src_list(self, df = None):
        groups1 = [self.random_mcast_ip()]
        groups2 = [self.random_mcast_ip()]
	self.onos_ssm_table_load(groups1 + groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','2.2.2.2', '5.5.5.5'])
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        src_ip = '2.2.2.2'
	dst_mac=self.iptomac(groups1[0])
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2'], iface = self.V_INF1, delay =2)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target2 == 2, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s after sending CHANGE_TO_EXCLUDE' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_change_to_exclude_src_list(self):
        df = defer.Deferred()
        def igmp_change_to_exclude_src_list():
              self.igmp_change_to_exclude_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_exclude_src_list)
        return df

    def igmp_include_to_allow_src_list(self, df = None):
        groups1 = [self.random_mcast_ip()] #(self.MGROUP1,)
	self.onos_ssm_table_load(groups1,src_list = ['4.4.4.4','6.6.6.6'])
	self.send_igmp_join(groups = groups1, src_list = ['4.4.4.4'],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
        src_ip = '4.4.4.4'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2',src_ip = src_ip,
					cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
	mcastTraffic1.stop()
	mcastTraffic2 = McastTraffic(groups1, iface= 'veth2',src_ip = '6.6.6.6',
                                        cb = self.send_mcast_cb, arg = igmpState1)
	self.send_igmp_join(groups = groups1, src_list = ['6.6.6.6'],record_type = IGMP_V3_GR_TYPE_ALLOW_NEW,
                                         iface = self.V_INF1)
	mcastTraffic2.start()
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        mcastTraffic2.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+30)
    def test_igmp_include_to_allow_src_list(self):
        df = defer.Deferred()
        def igmp_include_to_allow_src_list():
              self.igmp_include_to_allow_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_to_allow_src_list)
        return df

    def igmp_include_to_block_src_list(self, df = None):
        groups1 = [self.random_mcast_ip()]   #groups1 = (self.MGROUP1,)
	self.onos_ssm_table_load(groups1,src_list = ['4.4.4.4','6.6.6.6'])
	self.send_igmp_join(groups = groups1, src_list = ['4.4.4.4','6.6.6.6'],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2',src_ip = '6.6.6.6',
					cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
	mcastTraffic1.stop()
	self.send_igmp_join(groups = groups1, src_list = ['6.6.6.6'],record_type = IGMP_V3_GR_TYPE_BLOCK_OLD,
                                         iface = self.V_INF1)
	mcastTraffic2 = McastTraffic(groups1, iface= 'veth2',src_ip = '6.6.6.6',
                                        cb = self.send_mcast_cb, arg = igmpState1)
	mcastTraffic2.start()
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
	assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is still receiving traffic from old multicast group %s even after we send block for source list' %groups1)
        mcastTraffic2.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+30)
    def test_igmp_include_to_block_src_list(self):
        df = defer.Deferred()
        def igmp_include_to_block_src_list():
              self.igmp_include_to_block_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_to_block_src_list)
        return df


    def igmp_change_to_include_src_list(self, df = None):
        groups1 = [self.random_mcast_ip()]
	src_list = ['4.4.4.4','6.6.6.6']
	self.onos_ssm_table_load(groups1,src_list = src_list)
        self.send_igmp_leave(groups = groups1, src_list = src_list,
                             iface = self.V_INF1, delay = 2)
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2',src_ip = src_list[0],
                                          cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
	mcastTraffic1.stop()
        self.send_igmp_join(groups = groups1, src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
        mcastTraffic2 = McastTraffic(groups1, iface= 'veth2',src_ip = src_list[1],
                                        cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic2.start()
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        mcastTraffic2.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_change_to_include_src_list(self):
        df = defer.Deferred()
        def igmp_change_to_include_src_list():
              self.igmp_change_to_include_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_include_src_list)
        return df

    #this test case failing because group in include receiving multicast traffic from any of the source
    def igmp_exclude_to_allow_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
	self.onos_ssm_table_load(groups1+groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','6.6.6.6', '7.7.7.7', '8.8.8.8','5.5.5.5'])
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)

        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['6.6.6.6', '7.7.7.7', '8.8.8.8'], ['6.6.6.6', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_exclude_to_allow_src_list(self):
        df = defer.Deferred()
        def igmp_exclude_to_allow_src_list():
              self.igmp_exclude_to_allow_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_exclude_to_allow_src_list)
        return df

    def igmp_exclude_to_block_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
	self.onos_ssm_table_load(groups1+groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','7.7.7.7','5.5.5.5'])
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)

        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '7.7.7.7'],
                             iface = self.V_INF1, delay = 2)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_exclude_to_block_src_list(self):
        df = defer.Deferred()
        def igmp_exclude_to_block_src_list():
              self.igmp_exclude_to_block_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_exclude_to_block_src_list)
        return df

    #this test case failing because group in include mode recieves traffic from other sources also.
    def igmp_new_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
	self.onos_ssm_table_load(groups1+groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','5.5.5.5','6.6.6.6'])
        self.igmp_send_joins_different_groups_srclist(groups1+groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '6.6.6.6'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s after sending join with new source list' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_new_src_list(self):
        df = defer.Deferred()
        def igmp_new_src_list():
              self.igmp_new_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_new_src_list)
        return df

    def igmp_block_old_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
	self.onos_ssm_table_load(groups1+groups2,src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4','5.5.5.5','6.6.6.6','7.7.7.7'])
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s' %groups2)
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '7.7.7.7']),
                                                      intf = self.V_INF1, delay = 2)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target2 == 2, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s after sending join with block old source list' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_block_old_src_list(self):
        df = defer.Deferred()
        def igmp_block_old_src_list():
              self.igmp_block_old_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_block_old_src_list)
        return df

    def igmp_include_empty_src_list(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['0']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s when we sent join with source list is empty' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_include_empty_src_list(self):
        ## '''Disabling this test as scapy IGMP doesn't work with empty source lists'''
        df = defer.Deferred()
        def igmp_include_empty_src_list():
              self.igmp_include_empty_src_list(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_empty_src_list)
        return df

    def igmp_exclude_empty_src_list(self, df = None):
        groups2 = (self.MGROUP2,)
        self.send_igmp_leave(groups = groups2, src_list = ['0'], iface = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving multicast groups %s' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_exclude_empty_src_list(self):
        df = defer.Deferred()
        def igmp_exclude_empty_src_list():
              self.igmp_exclude_empty_src_list()
              df.callback(0)
        reactor.callLater(0, igmp_exclude_empty_src_list)
        return df

    def igmp_join_sourceip_0_0_0_0(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        ip_src = '0.0.0.0'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s when we sent join with source IP  is 0.0.0.0' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_join_sourceip_0_0_0_0(self):
        df = defer.Deferred()
        def igmp_join_sourceip_0_0_0_0():
              self.igmp_join_sourceip_0_0_0_0(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_join_sourceip_0_0_0_0)
        return df

    def igmp_invalid_join_packet(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MINVALIDGROUP1,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s when we sent invalid join packet ' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalid_join_packet(self):
        df = defer.Deferred()
        def igmp_invalid_join_packet():
              self.igmp_invalid_join_packet(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_invalid_join_packet)
        return df

    def igmp_join_data_receiving_during_subscriber_link_toggle(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups,  before bring down the self.V_INF1=%s  ' %self.V_INF1)
        os.system('ifconfig '+self.V_INF1+' down')
        log_test.info(' the self.V_INF1 %s is down now  ' %self.V_INF1)
        os.system('ifconfig '+self.V_INF1)
        time.sleep(10)
        os.system('ifconfig '+self.V_INF1+' up')
        os.system('ifconfig '+self.V_INF1)
        log_test.info(' the self.V_INF1 %s is up now  ' %self.V_INF1)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s when we nterface up after down  ' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_join_data_received_during_subscriber_link_toggle(self):
        df = defer.Deferred()
        def igmp_join_data_received_during_subscriber_link_toggle():
              self.igmp_join_data_received_during_subscriber_link_toggle(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_join_data_received_during_subscriber_link_toggle)
        return df

    def igmp_join_data_received_during_channel_distributor_link_toggle(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5', '6.6.6.6']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac1 = '01:00:5e:01:02:03'
        dst_mac2 = '01:00:5e:02:02:03'
        src_ip2 = '5.5.5.5'
        src_ip1 = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        igmpState2 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac1,
                                     src_ip = src_ip1, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic2 = McastTraffic(groups2, iface= 'veth3', dst_mac = dst_mac2,
                                     src_ip = src_ip2,  cb = self.send_mcast_cb, arg = igmpState2)
        mcastTraffic1.start()
        mcastTraffic2.start()
        join_state1 = IGMPTestState(groups = groups1)
        join_state2 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.igmp_recv_task(self.V_INF1, groups2, join_state2)
        mcastTraffic1.stop()
        os.system('ifconfig '+'veth2'+' down')
        os.system('ifconfig '+'veth2')
        time.sleep(10)
        self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        os.system('ifconfig '+'veth2'+' up')
        os.system('ifconfig '+'veth2')
        time.sleep(10)
        mcastTraffic1.start()
        self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        self.igmp_recv_task(self.V_INF1, groups2, join_state2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state2)
        mcastTraffic2.stop()

    ##  This test case is failing to receive traffic from multicast data from defferent channel interfaces TO-DO
    ###### TO DO scenario #######
    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+60)
    def test_igmp_join_data_received_during_channel_distributors_link_toggle(self):
        df = defer.Deferred()
        def igmp_join_data_receiving_during_channel_distributor_link_toggle():
              self.igmp_join_data_received_during_channel_distributor_link_toggle(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_join_data_receiving_during_channel_distributor_link_toggle)
        return df

    def igmp_invalidClassD_IP_join_packet(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MINVALIDGROUP2,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s when we sent invalid join packet ' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalid_class_d_ip_for_join_packet(self):
        df = defer.Deferred()
        def igmp_invalidClass_D_IP_join_packet():
              self.igmp_invalidClassD_IP_join_packet(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_invalidClass_D_IP_join_packet)
        return df

    def igmp_invalidClassD_IP_as_srclistIP_join_packet(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['239.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s when we sent invalid join packet ' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalid_class_d_ip_as_srclist_ip_for_join_packet(self):
        df = defer.Deferred()
        def igmp_invalidClassD_IP_as_srclistIP_join_packet():
              self.igmp_invalidClassD_IP_as_srclistIP_join_packet(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_invalidClassD_IP_as_srclistIP_join_packet)
        return df

    def igmp_general_query_recv_packet(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        ip_src = '1.1.1.1'
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2, ip_src = ip_src)
        ip_src = self.IP_SRC
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        log_test.info('Started delay to verify multicast data taraffic for group %s is received or not for 180 sec ' %groups2)
        time.sleep(100)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Verified that  multicast data for group %s is received after 100 sec ' %groups2)
        time.sleep(50)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Verified that  multicast data for group %s is received after 150 sec ' %groups2)
        time.sleep(30)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Verified that  multicast data for group %s is received after 180 sec ' %groups2)
        time.sleep(10)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Verified that  multicast data for group %s is received after 190 sec ' %groups2)
        target3 = mcastTraffic1.isRecvStopped()
        assert target3==False, 'EXPECTED FAILURE'
        log_test.info('Verified that multicast data for a group %s is still transmitting from a data interface' %groups2)
        log_test.info('Now checking join interface is receiving a multicast data for group %s after 190 sec' %groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving multicast data for group %s' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+250)
    def test_igmp_general_query_received_traffic(self):
        df = defer.Deferred()
        def igmp_general_query_recv_packet():
              self.igmp_general_query_recv_packet(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_general_query_recv_packet)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+100)
    def test_igmp_query_received_on_joining_interface(self):
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        log_test.info('Sending join packet and expect to receive on general query packet after 60 sec for multicast %s ' %groups)
        self.send_igmp_join_recvQuery(groups)
        log_test.info('Received a general query packet for multicast %s group on joing interface and sending traffic' %groups)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+190)
    def test_igmp_for_periodic_query_received_on_joining_interface(self):
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        self.send_igmp_join_recvQuery(groups,3)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+190)
    def test_igmp_for_periodic_query_received_and_checking_entry_deleted(self):
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        self.send_igmp_join_recvQuery(groups,3)
        log_test.info('Received periodic general query packets for multicast %s, now checking entry is deleted from tabel by sending traffic for that group' %groups)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+190)
    def test_igmp_member_query_interval_and_expiry_for_rejoining_interface(self):
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        self.send_igmp_join_recvQuery(groups,3)
        log_test.info('Received periodic general query packets for multicast %s, now sending join packet again and verifying traffic for that group is received or not on joining interface' %groups)
        self.send_igmp_join(groups)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+50)
    def test_igmp_leave_received_group_and_source_specific_query(self):
        groups = ['224.0.1.10', '225.0.0.10']
        leave_groups = ['224.0.1.10']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                    arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        self.send_igmp_join(groups)
        self.send_igmp_leave_listening_group_specific_query(leave_groups, delay = 3)
        return df

    def igmp_change_to_exclude_src_list_check_for_group_source_specific_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.send_igmp_leave_listening_group_specific_query(groups = groups1, src_list = ['2.2.2.2'], iface = self.V_INF1, delay =2)
        time.sleep(10)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target2 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s after sending CHANGE_TO_EXCLUDE' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+60)
    def test_igmp_change_to_exclude_src_list_and_check_for_group_source_specific_query(self):
        df = defer.Deferred()
        def igmp_change_to_exclude_src_list_check_for_group_source_specific_query():
              self.igmp_change_to_exclude_src_list_check_for_group_source_specific_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_exclude_src_list_check_for_group_source_specific_query)
        return df

    def igmp_change_to_include_src_list_check_for_general_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist_wait_query_packets(groups1 + groups2,
                                                   (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['6.6.6.6', '5.5.5.5']),
                                                    intf = self.V_INF1, delay = 2,query_group1 = 'group1', query_group2 = None)
        time.sleep(10)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s after send Change to include message' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+80)
    def test_igmp_change_to_include_src_list_and_check_for_general_query(self):
        df = defer.Deferred()
        def igmp_change_to_include_src_list_check_for_general_query():
              self.igmp_change_to_include_src_list_check_for_general_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_include_src_list_check_for_general_query)
        return df

    def igmp_allow_new_src_list_check_for_general_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1+groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '6.6.6.6'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist_wait_query_packets(groups1 + groups2,                                                                              (['2.2.2.2', '6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                              intf = self.V_INF1, delay = 2, query_group1 = 'group1', query_group2 = None)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s after sending join with new source list' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+80)
    def test_igmp_allow_new_src_list_and_check_for_general_query(self):
        df = defer.Deferred()
        def igmp_allow_new_src_list_check_for_general_query():
              self.igmp_allow_new_src_list_check_for_general_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_allow_new_src_list_check_for_general_query)
        return df

    def igmp_block_old_src_list_check_for_group_source_specific_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log_test.info('Interface is receiving traffic from multicast groups %s' %groups2)
        self.igmp_send_joins_different_groups_srclist_wait_query_packets(groups,
                                                (['6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '7.7.7.7']),
                                                intf = self.V_INF1, delay = 2, query_group1 = 'group1', query_group2 = None)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target2 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s after sending join with block old source list' %groups2)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+90)
    def test_igmp_block_old_src_list_and_check_for_group_source_specific_query(self):
        df = defer.Deferred()
        def igmp_block_old_src_list_check_for_group_source_specific_query():
              self.igmp_block_old_src_list_check_for_group_source_specific_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_block_old_src_list_check_for_group_source_specific_query)
        return df

    def igmp_include_to_allow_src_list_check_for_general_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.igmp_send_joins_different_groups_srclist_wait_query_packets(groups1 + groups2,(['2.2.2.2', '3.3.3.3', '4.4.4.4', '6.6.6.6'], ['2.2.2.2', '5.5.5.5']),                                               intf = self.V_INF1, delay = 2, query_group1 = 'group1', query_group2 = None)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+40)
    def test_igmp_include_to_allow_src_list_and_check_for_general_query(self):
        df = defer.Deferred()
        def igmp_include_to_allow_src_list_check_for_general_query():
              self.igmp_include_to_allow_src_list_check_for_general_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_to_allow_src_list_check_for_general_query)
        return df

    def igmp_include_to_block_src_list_check_for_group_source_specific_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.send_igmp_leave_listening_group_specific_query(groups = groups1, src_list = ['6.6.6.6','7.7.7.7'],
                             iface = self.V_INF1, delay = 2)
        self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+40)
    def test_igmp_include_to_block_src_list_and_check_for_group_source_specific_query(self):
        df = defer.Deferred()
        def igmp_include_to_block_src_list_check_for_group_source_specific_query():
              self.igmp_include_to_block_src_list_check_for_group_source_specific_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_to_block_src_list_check_for_group_source_specific_query)
        return df

    def igmp_exclude_to_allow_src_list_check_for_general_query(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)

        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist_wait_query_packets(groups1 + groups2,
                                             (['6.6.6.6', '7.7.7.7', '8.8.8.8'], ['6.6.6.6', '5.5.5.5']),                                                                 intf = self.V_INF1, delay = 2, query_group1 = 'group1', query_group2 = None)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+90)
    def test_igmp_exclude_to_allow_src_list_and_check_for_general_query(self):
        df = defer.Deferred()
        def igmp_exclude_to_allow_src_list_check_for_general_query():
              self.igmp_exclude_to_allow_src_list_check_for_general_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_exclude_to_allow_src_list_check_for_general_query)
        return df

    def igmp_exclude_to_block_src_list_check_for_group_source_specific_query(self, df = None):
        groups1 = (self.MGROUP1,)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)

        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        self.send_igmp_leave_listening_group_specific_query(groups = groups1,
                                          src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '7.7.7.7'],
                                          iface = self.V_INF1, delay = 2)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log_test.info('Interface is not receiving traffic from multicast groups %s' %groups1)
        mcastTraffic1.stop()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+40)
    def test_igmp_exclude_to_block_src_list_and_check_for_group_source_specific_query(self):
        df = defer.Deferred()
        def igmp_exclude_to_block_src_list_check_for_group_source_specific_query():
              self.igmp_exclude_to_block_src_list_check_for_group_source_specific_query(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_exclude_to_block_src_list_check_for_group_source_specific_query)
        return df

    def iptomac(self, mcast_ip):
        mcast_mac =  '01:00:5e:'
        octets = mcast_ip.split('.')
        second_oct = int(octets[1]) & 127
        third_oct = int(octets[2])
        fourth_oct = int(octets[3])
        mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
        return mcast_mac

    def send_multicast_data_traffic(self, group, intf= 'veth2',source = '1.2.3.4'):
        dst_mac = self.iptomac(group)
        eth = Ether(dst= dst_mac)
        ip = IP(dst=group,src=source)
        data = repr(monotonic.monotonic())
        sendp(eth/ip/data,count=20, iface = intf)

    def verify_igmp_data_traffic(self, group, intf='veth0', source='1.2.3.4' ):
        log_test.info('verifying multicast traffic for group %s from source %s'%(group,source))
        self.success = False
        def recv_task():
            def igmp_recv_cb(pkt):
                #log_test.info('received multicast data packet is %s'%pkt.show())
                log_test.info('multicast data received for group %s from source %s'%(group,source))
                self.success = True
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].dst == group and p[IP].src == source, count=1,timeout = 2, iface='veth0')
        t = threading.Thread(target = recv_task)
        t.start()
        self.send_multicast_data_traffic(group,source=source)
        t.join()
        return self.success

    def test_igmp_include_exclude_modes(self):
        groups = ['224.2.3.4','230.5.6.7']
        src_list = ['2.2.2.2','3.3.3.3']
        self.onos_ssm_table_load(groups, src_list=src_list)
        self.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
        self.send_igmp_join(groups = [groups[1]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                             iface = self.V_INF1, delay = 2)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        status = self.verify_igmp_data_traffic(groups[1],intf = self.V_INF1,source= src_list[1])
        assert_equal(status,False)

    def test_igmp_allow_new_source_mode(self):
        group = ['224.8.9.3']
        src_list = ['2.2.2.2','3.3.3.3']
        #dst_mac = self.iptomac(group[0])
        self.onos_ssm_table_load(group, src_list)
        self.send_igmp_join(groups = group, src_list = src_list[0],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(group[0], intf=self.V_INF1,source = src_list[0])
        assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
        self.send_igmp_join(groups = group, src_list = src_list[1],record_type = IGMP_V3_GR_TYPE_ALLOW_NEW,
                            iface = self.V_INF1, delay = 1)
        for src in src_list:
            status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1, source=src)
            assert_equal(status,True) # expecting igmp data traffic from both sources


    def test_igmp_include_to_exclude_mode_change(self):
        group = ['224.2.3.4']
        src_list = ['2.2.2.2','3.3.3.3']
        self.onos_ssm_table_load(group, src_list)
        self.send_igmp_join(groups = group, src_list = src_list[0],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source= src_list[0])
        assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
        self.send_igmp_join(groups = group, src_list = src_list[1],record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                           iface = self.V_INF1, delay = 1)
        for src in src_list:
            status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source= src)
            assert_equal(status,False) # expecting igmp data traffic from both sources

    def test_igmp_exclude_to_include_mode_change(self):
        group = ['224.2.3.4']
        src = ['2.2.2.2']
        self.onos_ssm_table_load(group, src)
        self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src[0])
        assert_equal(status,False) # not expecting igmp data traffic from source src_list[0]
        self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source = src[0])
        assert_equal(status,True) # expecting igmp data traffic from both sources

    #this test case wotks properly if the snooping device(ONOS) have multicast router connected.
    def test_igmp_to_include_mode_with_null_source(self):
        groups = ['224.2.3.4','230.7.9.8']
        src = ['192.168.12.34']
        dst_mac = []
        dst_mac.append(self.iptomac(groups[0]))
        dst_mac.append(self.iptomac(groups[1]))
        self.onos_ssm_table_load(groups, src)
        self.send_igmp_join(groups = groups, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        for grp in groups:
            status = self.verify_igmp_data_traffic(grp,intf=self.V_INF1,source= src[0])
            assert_equal(status,True) # not expecting igmp data traffic from source src_list[0]
        #sending leave packet for group groups[1]
        self.send_igmp_join(groups = [groups[1]], src_list = [],record_type = IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        for grp in groups:
            status = self.verify_igmp_data_traffic(grp,intf=self.V_INF1,source= src[0])
            if grp is groups[0]:
                assert_equal(status,True) # expecting igmp data traffic to group groups[0]
            else:
                assert_equal(status,False) # not expecting igmp data traffic to group groups[1]

    def test_igmp_to_include_mode(self):
        group = ['229.9.3.6']
        src_list = ['192.168.12.34','192.18.1.34']
        self.onos_ssm_table_load(group, src_list)
        self.send_igmp_join(groups = group, src_list = [src_list[0]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True) # not expecting igmp data traffic from source src_list[0]
        self.send_igmp_join(groups = group, src_list = src_list,record_type = IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        for src in src_list:
            status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source= src)
            assert_equal(status,True) # expecting igmp data traffic to group groups[0]

    #this test case passed only if mulitcast router connected to ONOS.
    def test_igmp_blocking_old_source_mode(self):
        group = ['224.2.3.4']
        src_list = ['2.2.2.2','3.3.3.3']
        self.onos_ssm_table_load(group, src_list)
        self.send_igmp_join(groups = group, src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        for src in src_list:
            status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1, source=src)
            assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
        self.send_igmp_join(groups = group, src_list = [src_list[1]],record_type = IGMP_V3_GR_TYPE_BLOCK_OLD,
                             iface = self.V_INF1, delay = 1)
        for src in src_list:
            status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1, source=src)
            if src is src_list[0]:
                assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
            else:
                assert_equal(status,False) # not expecting igmp data traffic from source src_list[1]

    def test_igmp_multiple_joins_and_data_verification_with_100_groups(self):
        groups = []
	sources = []
	count = 1
	mcastips = self.mcast_ip_range(start_ip = '226.0.0.1',end_ip = '226.0.5.254')
	sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = '10.10.5.254')
        while count<=100:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
	    if group in groups:
		pass
	    else:
		log_test.info('group and source are %s and %s'%(group,source))
		groups.append(group)
                sources.append(source)
		count += 1
	self.onos_ssm_table_load(groups,src_list=sources,flag=True)
	for i in range(100):
	    self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, True)
	    log_test.info('data received for group %s from source %s'%(groups[i],sources[i]))

    def test_igmp_multiple_joins_with_data_verification_and_leaving_100_groups(self):
        groups = []
        sources = []
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '226.0.0.1',end_ip = '226.0.5.254')
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = '10.10.5.254')
        while count<=100:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            if group in groups:
                pass
            else:
                log_test.info('group and source are %s and %s'%(group,source))
                groups.append(group)
                sources.append(source)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for i in range(100):
            self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s'%(groups[i],sources[i]))
	    self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE,
                                         iface = self.V_INF1, delay = 1)
	    status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, False)
            log_test.info("data not received for group %s from source %s after changing group mode to 'TO-EXCLUDE' mode"%(groups[i],sources[i]))

    def test_igmp_group_source_for_only_config_with_1000_entries(self):
        groups = []
        sources = []
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '229.0.0.1',end_ip = '229.0.50.254')
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = '10.10.50.254')
        while count<=1000:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            if group in groups:
                pass
            else:
                log_test.info('group and source are %s and %s'%(group,source))
                groups.append(group)
                sources.append(source)
                count += 1
	self.onos_ssm_table_load(groups,src_list=sources,flag=True)

    def test_igmp_from_exclude_to_include_mode_with_100_groups(self):
        groups = []
        sources = []
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '229.0.0.1',end_ip = '229.0.10.254')
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = '10.10.10.254')
        while count<=100:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            if group in groups:
                pass
            else:
                log_test.info('group and source are %s and %s'%(group,source))
                groups.append(group)
                sources.append(source)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for i in range(100):
            self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, False)
	    log_test.info('data not received for group %s from source %s as expected'%(groups[i],sources[i]))
	    self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
	    status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
	    assert_equal(status, True)
            log_test.info("data received for group %s from source %s after changing group mode to 'TO-INCLUDE' mode"%(groups[i],sources[i]))

    def test_igmp_with_multiple_joins_and_data_verify_with_1000_groups(self):
        groups = []
        sources = []
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '229.0.0.1',end_ip = '229.0.30.254')
        sourceips = self.source_ip_range(start_ip = '10.10.0.1',end_ip = '10.10.30.254')
        while count<=1000:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            if group in groups:
                pass
            else:
                log_test.info('group and source are %s and %s'%(group,source))
                groups.append(group)
                sources.append(source)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for i in range(1000):
            self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[i],sources[i],i))

    def test_igmp_with_multiple_joins_and_data_verify_with_5000_groups(self):
        groups = []
        sources = []
        count = 1
        mcastips = self.mcast_ip_range(start_ip = '231.39.19.121',end_ip = '231.40.30.25')
        sourceips = self.source_ip_range(start_ip = '192.168.56.43',end_ip = '192.169.110.30')
        while count<=5000:
            group = random.choice(mcastips)
            source = random.choice(sourceips)
            if group in groups:
                pass
            else:
                log_test.info('group and source are %s and %s'%(group,source))
                groups.append(group)
                sources.append(source)
                count += 1
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for i in range(5000):
            self.send_igmp_join(groups = [groups[i]], src_list = [sources[i]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[i],intf=self.V_INF1,source=sources[i])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[i],sources[i],i))

    """def test_igmp_join_from_multiple_infts(self):
        groups = ['229.9.3.6','234.20.56.2']
        src_list = ['192.168.12.34','192.18.1.34']
        self.onos_ssm_table_load(groups, src_list=src_list)
        self.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = 'veth0')
	self.send_igmp_join(groups = [groups[1]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = 'veth2')
        status = self.verify_igmp_data_traffic(groups[0],intf='veth0',source=src_list[0])
	assert_equal(status,True)
	status = self.verify_igmp_data_traffic(groups[1],intf='veth2',source=src_list[1])
        assert_equal(status,True) # not expecting igmp data traffic from source src_list[0]
    """

    def test_igmp_send_data_to_non_registered_group(self):
        group = ['224.2.3.4']
        src = ['2.2.2.2']
        self.onos_ssm_table_load(group,src_list= src)
        self.send_igmp_join(groups = ['239.0.0.1'], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic('239.0.0.1',intf=self.V_INF1,source=src[0])
        assert_equal(status,False) # not expecting igmp data traffic from source src_list[0]

    def test_igmp_traffic_verification_for_registered_group_with_no_join_sent(self):
        group = ['227.12.3.40']
        src = ['190.4.19.67']
        self.onos_ssm_table_load(group,src_list= src)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src[0])
        assert_equal(status,False) # not expecting igmp data traffic from source src_list[0]

    def test_igmp_toggling_app_activation(self):
        group = [self.random_mcast_ip()]
        src = [self.randomsourceip()]
        self.onos_ssm_table_load(group,src_list= src)
	self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1)
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src[0])
        assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
	log_test.info('Multicast traffic received for group %s from source %s before the app is deactivated'%(group[0],src[0]))
	self.onos_ctrl.deactivate()
	status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src[0])
        assert_equal(status,False) #not expecting igmp data traffic from source src_list[0]
	log_test.info('Multicast traffic not received for group %s from source %s after the app is deactivated'%(group[0],src[0]))
	self.onos_ctrl.activate()
        status = self.verify_igmp_data_traffic(group[0],intf=self.V_INF1,source=src[0])
        assert_equal(status,True) # expecting igmp data traffic from source src_list[0]
	log_test.info('Multicast traffic received for group %s from source %s the app is re-activated'%(group[0],src[0]))

    def test_igmp_with_mismatch_for_dst_ip_and_mac_in_data_packets(self):
        group = ['228.18.19.29']
        source = [self.randomsourceip()]
        self.onos_ssm_table_load(group,src_list= source)
	self.send_igmp_join(groups = group, src_list = source,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1)
        dst_mac = '01:00:5e:0A:12:09'
        eth = Ether(dst= dst_mac)
        ip = IP(dst=group[0],src=source[0])
        data = repr(monotonic.monotonic())
        pkt = (eth/ip/data)
        log_test.info('Multicast traffic packet %s'%pkt.show())
	self.success = False
        def recv_task():
            def igmp_recv_cb(pkt):
                #log_test.info('received multicast data packet is %s'%pkt.show())
                log_test.info('multicast data received for group %s from source %s'%(group[0],source[0]))
                self.success = True
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].dst == group[0] and p[IP].src == source[0], count=1,timeout = 2, iface='veth0')
        t = threading.Thread(target = recv_task)
        t.start()
        sendp(eth/ip/data,count=20, iface = 'veth2')
        t.join()
        assert_equal(status,False) # not expecting igmp data traffic from source src_list[0]

    #test case failing, ONOS registering unicast ip also as an igmp join
    def test_igmp_registering_invalid_group(self):
        groups = ['218.18.19.29']
        source = [self.randomsourceip()]
	ssm_dict = {'apps' : { 'org.opencord.igmp' : { 'ssmTranslate' : [] } } }
	ssm_xlate_list = ssm_dict['apps']['org.opencord.igmp']['ssmTranslate']
	for g in groups:
            for s in source:
                d = {}
                d['source'] = s or '0.0.0.0'
                d['group'] = g
                ssm_xlate_list.append(d)
	    log_test.info('onos load config is %s'%ssm_dict)
            status, code = OnosCtrl.config(ssm_dict)
        self.send_igmp_join(groups, src_list = source, record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 1)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1, source=source[0])
        assert_equal(status,False) # not expecting igmp data traffic from source src_list[0]

    def test_igmp_registering_invalid_source(self):
        groups = [self.random_mcast_ip()]
        sources = ['224.10.28.34','193.73.219.257']
        ssm_dict = {'apps' : { 'org.opencord.igmp' : { 'ssmTranslate' : [] } } }
        ssm_xlate_list = ssm_dict['apps']['org.opencord.igmp']['ssmTranslate']
        for g in groups:
            for s in sources:
                d = {}
                d['source'] = s or '0.0.0.0'
                d['group'] = g
                ssm_xlate_list.append(d)
            log_test.info('onos load config is %s'%ssm_dict)
            status, code = OnosCtrl.config(ssm_dict)
            assert_equal(status,False)
