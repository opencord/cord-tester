import unittest
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from scapy.all import *
import time, monotonic
import os, sys
import tempfile
import random
import threading

CORD_TEST_UTILS = 'utils'
test_root = os.getenv('CORD_TEST_ROOT') or './'
sys.path.append(test_root + CORD_TEST_UTILS)
from IGMP import *
from McastTraffic import *
from Stats import Stats
from OnosCtrl import OnosCtrl
log.setLevel('INFO')

IGMP_DST_MAC = "01:00:5e:00:01:01"
IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
IP_SRC = '1.2.3.4'
IP_DST = '224.0.1.1'

igmp_eth = Ether(dst = IGMP_DST_MAC, src = IGMP_SRC_MAC, type = ETH_P_IP)
igmp_ip = IP(dst = IP_DST, src = IP_SRC)

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

class igmp_exchange(unittest.TestCase):

    IGMP_TEST_TIMEOUT = 5
    MCAST_TRAFFIC_TIMEOUT = 10
    max_packets = 100
    app = 'org.onosproject.igmp'

    def setUp(self):
        ''' Activate the dhcp app'''
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)

    def teardown(self):
        '''Deactivate the dhcp app'''
        self.onos_ctrl.deactivate()

    def onos_load_config(self, config):
        status, code = self.onos_ctrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)
          
    def onos_ssm_table_load(self, groups, src_list):
          ssm_dict = {'apps' : { 'org.onosproject.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.onosproject.igmp']['ssmTranslate']
          for g in groups:
                for s in src_list:
                      d = {}
                      d['source'] = s
                      d['group'] = g
                      ssm_xlate_list.append(d)
          self.onos_load_config(ssm_dict)
          time.sleep(2)

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
        send_time = float(p.payload.load)
        recv_time = monotonic.monotonic()
        #log.info( 'Recv in %.6f secs' %(recv_time - send_time))
        igmpState.update(p.dst, rx = 1, t = recv_time - send_time)
        return 0

    def send_igmp_join(self, groups, src_list = ['1.2.3.4'], iface = 'veth0', delay = 2):
        self.onos_ssm_table_load(groups, src_list)
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr='224.0.1.1')
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)

        pkt = igmp_eth/igmp_ip/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface=iface)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave(self, groups, src_list = ['1.2.3.4'], iface = 'veth0', delay = 2):
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr='224.0.1.1')
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)

        pkt = igmp_eth/igmp_ip/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface = iface)
        if delay != 0:
            time.sleep(delay)

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_join_verify_traffic(self):
        groups = ['224.0.1.1', '225.0.0.1']
        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        igmpStateRecv = IGMPTestState(groups = groups, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        mcastTraffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb, arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = 'veth0', type = ETH_P_IP)

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
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_leave_verify_traffic(self):
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
                result = self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                self.recv_socket.close()
                self.igmp_verify_leave(stateList, leave_groups)
                self.df.callback(0)

        self.send_igmp_join(groups)
        self.send_igmp_leave(leave_groups, delay = 3)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(timeout=100)
    def test_igmp_leave_join_loop(self):
        self.groups = ['226.0.1.1', '227.0.0.1', '228.0.0.1', '229.0.0.1', '230.0.0.1' ]
        self.src_list = ['3.4.5.6', '7.8.9.10']
        df = defer.Deferred()
        self.df = df
        self.iterations = 0
        self.num_groups = len(self.groups)
        self.MAX_TEST_ITERATIONS = 10

        def igmp_srp_task(v):
              if self.iterations < self.MAX_TEST_ITERATIONS:
                    if v == 1:
                          ##join test
                          self.num_groups = random.randint(0, len(self.groups))
                          self.send_igmp_join(self.groups[:self.num_groups],
                                              src_list = self.src_list,
                                              iface = 'veth0', delay = 0)
                    else:
                          self.send_igmp_leave(self.groups[:self.num_groups],
                                               src_list = self.src_list,
                                               iface = 'veth0', delay = 0)
                    self.iterations += 1
                    v ^= 1
                    reactor.callLater(1.0 + 0.5*self.num_groups,
                                      igmp_srp_task, v)
              else:
                    self.df.callback(0)

        reactor.callLater(0, igmp_srp_task, 1)
        return df

    def igmp_join_task(self, intf, groups, state, src_list = ['1.2.3.4']):
          self.onos_ssm_table_load(groups, src_list)
          igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                        gaddr='224.0.1.1')
          for g in groups:
                gr = IGMPv3gr(rtype = IGMP_V3_GR_TYPE_EXCLUDE, mcaddr = g)
                gr.sources = src_list
                igmp.grps.append(gr)

          for g in groups:
                state.group_map[g][0].update(1, t = monotonic.monotonic())

          pkt = igmp_eth/igmp_ip/igmp
          IGMPv3.fixup(pkt)
          sendp(pkt, iface=intf)
          log.debug('Returning from join task')

    def igmp_recv_task(self, intf, groups, join_state):
          recv_socket = L3PacketSocket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

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
                log.info('Join for group %s received in %.3f usecs' %
                         (g, delta))

          recv_socket.close()
          log.debug('Returning from recv task')
          
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

    def test_igmp_1group_join_latency(self):
          groups = ['239.0.1.1']
          self.group_latency_check(groups)

    def test_igmp_2group_join_latency(self):
          groups = ['239.0.1.1', '240.0.1.1']
          self.group_latency_check(groups)

    def test_igmp_Ngroup_join_latency(self):
          groups = ['239.0.1.1', '240.0.1.1', '241.0.1.1', '242.0.1.1']
          self.group_latency_check(groups)

          
