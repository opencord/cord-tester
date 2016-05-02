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
from IGMP import *
from McastTraffic import *
from Stats import Stats
from OnosCtrl import OnosCtrl
from Channels import IgmpChannel
log.setLevel('INFO')

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

    V_INF1 = 'veth0'
    V_INF2 = 'veth1'
    MGROUP1 = '239.1.2.3'
    MGROUP2 = '239.2.2.3'
    MMACGROUP1 = "01:00:5e:01:02:03"
    MMACGROUP2 = "01:00:5e:02:02:03"
    MINVALIDGROUP1 = "255.255.255.255"
    MINVALIDGROUP2 = "255.255.255.255"
    IGMP_DST_MAC = "01:00:5e:00:01:01"
    IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
    IP_SRC = '1.2.3.4'
    IP_DST = '224.0.1.1'
    igmp_eth = Ether(dst = IGMP_DST_MAC, src = IGMP_SRC_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST, src = IP_SRC)
    IGMP_TEST_TIMEOUT = 5
    IGMP_QUERY_TIMEOUT = 30
    MCAST_TRAFFIC_TIMEOUT = 10
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    app = 'org.onosproject.igmp'

    def setUp(self):
        ''' Activate the dhcp app'''
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(2)
        self.igmp_channel = IgmpChannel()

    def teardown(self):
        '''Deactivate the dhcp app'''
        self.onos_ctrl.deactivate()

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
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
                      d['source'] = s or '0.0.0.0'
                      d['group'] = g
                      ssm_xlate_list.append(d)
          self.onos_load_config(ssm_dict)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          self.igmp_channel.cord_port_table_load(cord_port_map)
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

    def send_igmp_join(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
        self.onos_ssm_table_load(groups, src_list)
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
        sendp(pkt, iface=iface)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=g)
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
                        gaddr=self.IP_DST)
          for g in groups:
                gr = IGMPv3gr(rtype = IGMP_V3_GR_TYPE_EXCLUDE, mcaddr = g)
                gr.sources = src_list
                igmp.grps.append(gr)

          for g in groups:
                state.group_map[g][0].update(1, t = monotonic.monotonic())

          pkt = self.igmp_eth/self.igmp_ip/igmp
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

    def igmp_not_recv_task(self, intf, groups, join_state):
          recv_socket = L2Socket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log.info('Should not receive any multicast data')
          status = 1
          def igmp_recv_cb(pkt):
                log.info('Multicast packet %s received for left groups %s' %(pkt[IP].dst, groups))
                status = 2
          sniff(prn = igmp_recv_cb, count = 1, lfilter = lambda p: p[IP].dst in groups,
                timeout = 3, opened_socket = recv_socket)
          recv_socket.close()
          return status

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

          
    def test_igmp_join_rover(self):
          '''Keep sending joins across multicast range of addresses'''
          '''For now, restricting it to 50/100'''
          s = (224 << 24) | 1
          #e = (225 << 24) | (255 << 16) | (255 << 16) | 255
          e = (224 << 24) | 10
          for i in xrange(s, e+1):
                if i&0xff:
                      ip = '%d.%d.%d.%d'%((i>>24)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
                self.send_igmp_join([ip], delay = 0)

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmp_query(self):
        groups = ['224.0.0.1'] ##igmp query group
        df = defer.Deferred()
        self.df = df
        self.recv_socket = L2Socket(iface = 'veth0', type = ETH_P_IP)
        
        def igmp_query_timeout():
              def igmp_query_cb(pkt):
                    log.info('Got IGMP query packet from %s for %s' %(pkt[IP].src, pkt[IP].dst))
                    assert_equal(pkt[IP].dst, '224.0.0.1')

              sniff(prn = igmp_query_cb, count=1, lfilter = lambda p: p[IP].dst in groups,
                    opened_socket = self.recv_socket)
              self.recv_socket.close()
              self.df.callback(0)

        self.send_igmp_join(groups)
        self.test_timer = reactor.callLater(self.IGMP_QUERY_TIMEOUT, igmp_query_timeout)
        return df

    def igmp_send_joins_different_groups_srclist(self, groups, sources, intf = V_INF1, delay = 2, ip_src = None):
        g1 = groups[0]
        g2 = groups[1]
        sourcelist1 = sources[0]
        sourcelist2 = sources[1]
        eth = Ether(dst = self.MMACGROUP1, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
        src_ip = ip_src or self.IP_SRC
        ip = IP(dst = g1, src = src_ip)
        log.info('Sending join message for the group %s' %g1)
        self.send_igmp_join((g1,), src_list = sourcelist1, ip_pkt = eth/ip, iface = intf, delay = 2)
        eth = Ether(dst = self.MMACGROUP2, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
        ip = IP(dst = g2, src = src_ip)
        log.info('Sending join message for group %s' %g2)
        self.send_igmp_join((g2,), src_list = sourcelist2, ip_pkt = eth/ip, iface = intf, delay = 2)

    def igmp_joins_leave_functionality(self, again_join = False, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2'], ['2.2.2.2']), intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        igmpStateRecv1 = IGMPTestState(groups = groups1, df = df)
        igmpStateList1 = (igmpState1, igmpStateRecv1)

        igmpState2 = IGMPTestState(groups = groups2, df = df)
        igmpStateRecv2 = IGMPTestState(groups = groups2, df = df)
        igmpStateList2 = (igmpState2, igmpStateRecv2)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb,
                                     arg = igmpState1)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '2.2.2.2'
        mcastTraffic2 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb,
                                     arg = igmpState2)
        mcastTraffic1.start()
        mcastTraffic2.start()
        join_state1 = IGMPTestState(groups = groups1)
        join_state2 = IGMPTestState(groups = groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log.info('Interface is receiving multicast groups %s' %groups1)
        target2 = self.igmp_recv_task(self.V_INF1, groups2, join_state2)
        log.info('Interface is receiving multicast groups %s' %groups2)
        log.info('Interface is sending leave message for groups %s now' %groups2)
        self.send_igmp_leave(groups = groups2, src_list = ['2.2.2.2'], iface = self.V_INF1, delay = 2)
        target3 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        target4 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state2)
        assert target4 == 1, 'EXPECTED FAILURE'
        if again_join:
            dst_mac = '01:00:5e:02:02:03'
            ip_dst = '239.2.2.3'
            eth = Ether(dst = dst_mac, src = self.IGMP_SRC_MAC, type = ETH_P_IP)
            ip = IP(dst = ip_dst, src = self.IP_SRC)
            log.info('Interface sending join message again for the groups %s' %groups2)
            self.send_igmp_join(groups2, src_list = [src_ip], ip_pkt = eth/ip, iface = self.V_INF1, delay = 2)
            target5 = self.igmp_recv_task(self.V_INF1, groups2, join_state2)
            log.info('Interface is receiving multicast groups %s again' %groups2)
            target6 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
            log.info('Interface is still receiving from multicast groups %s' %groups1)
        else:
            log.info('Ended test case')
        mcastTraffic1.stop()
        mcastTraffic2.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_2joins_1leave_functionality(self):
        '''This test is subscribing to two channels and sending leave for one channel'''
        df = defer.Deferred()
        def test_igmp_2joins_1leave():
              self.igmp_joins_leave_functionality(again_join = False, df = df)
              df.callback(0)
        reactor.callLater(0, test_igmp_2joins_1leave)
        return df

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+25)
    def test_igmp_2joins_1leave_again_joins_functionality(self):
        '''This test is subscribing to two channels and sending leave for one channel,again join to the same group'''
        df = defer.Deferred()
        def test_igmp_2joins_1leave_join_again():
              self.igmp_joins_leave_functionality(again_join = True, df = df)
              df.callback(0)
        reactor.callLater(0, test_igmp_2joins_1leave_join_again)
        return df

    def igmp_not_src_list_functionality(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                     (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '6.6.6.6'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        igmpStateRecv1 = IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface = 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s' %groups1)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_not_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude A,D'''
        df = defer.Deferred()
        def igmp_not_src_list_functionality():
              self.igmp_not_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_not_src_list_functionality)
        return df

    def igmp_change_to_exclude_src_list_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2'], iface = self.V_INF1, delay =2)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target2 == 1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s after sending CHANGE_TO_EXCLUDE' %groups1)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_change_to_exclude_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude A,D'''
        df = defer.Deferred()
        def igmp_change_to_exclude_src_list_functionality():
              self.igmp_change_to_exclude_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_exclude_src_list_functionality)
        return df

    def igmp_change_to_include_src_list_functionality(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        self.send_igmp_leave(groups = groups1, src_list = ['2.2.2.2', '3.3.3.3', '4.4.4.4'],
                             iface = self.V_INF1, delay = 2)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['6.6.6.6', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:01:02:03'
        src_ip = '2.2.2.2'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups1, df = df)
        igmpStateRecv1 = IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1= self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['6.6.6.6', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        target2 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log.info('Interface is receiving from multicast groups %s after send Change to include message' %groups1)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_change_to_include_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude D,E'''
        df = defer.Deferred()
        def igmp_change_to_include_src_list_functionality():
              self.igmp_change_to_include_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_change_to_include_src_list_functionality)
        return df

    def igmp_new_src_list_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups1, df = df)
        mcastTraffic1 = McastTraffic(groups1, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups1)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups1, join_state1)
        assert target1 == 1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s' %groups1)
        self.igmp_send_joins_different_groups_srclist(groups1 + groups2,
                                                      (['6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '5.5.5.5']),
                                                      intf = self.V_INF1, delay = 2)
        target2 = self.igmp_recv_task(self.V_INF1, groups1, join_state1)
        log.info('Interface is receiving from multicast groups %s after sending join with new source list' %groups1)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+10)
    def test_igmp_new_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude A,D'''
        df = defer.Deferred()
        def igmp_new_src_list_functionality():
              self.igmp_new_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_new_src_list_functionality)
        return df

    def igmp_block_old_src_list_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log.info('Interface is receiving from multicast groups %s' %groups2)
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['6.6.6.6', '3.3.3.3', '4.4.4.4'], ['2.2.2.2', '7.7.7.7']),
                                                      intf = self.V_INF1, delay = 2)
        target2 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target2 == 1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s after sending join with block old source list' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_block_old_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude A,D'''
        df = defer.Deferred()
        def igmp_block_old_src_list_functionality():
              self.igmp_block_old_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_block_old_src_list_functionality)
        return df

    def igmp_include_empty_src_list_functionality(self, df = None):
        print'This test is sending join with source list A,B,C and exclude D,F,G'
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        self.igmp_send_joins_different_groups_srclist(groups,
                                                      (['2.2.2.2', '3.3.3.3', '4.4.4.4'], ['']),
                                                      intf = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving from multicast groups %s when we sent join with source list is empty' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def ztest_igmp_include_empty_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude D,F,G'''
        '''Disabling this test as scapy IGMP doesn't work with empty source lists'''
        df = defer.Deferred()
        def igmp_include_empty_src_list_functionality():
              self.igmp_include_empty_src_list_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_include_empty_src_list_functionality)
        return df

    def igmp_exclude_empty_src_list_functionality(self, df = None):
        groups1 = (self.MGROUP1,)
        groups2 = (self.MGROUP2,)
        groups = groups1 + groups2
        self.send_igmp_leave(groups = groups2, src_list = [''], iface = self.V_INF1, delay = 2)
        dst_mac = '01:00:5e:02:02:03'
        src_ip = '5.5.5.5'
        if df is None:
              df = defer.Deferred()
        igmpState1 = IGMPTestState(groups = groups2, df = df)
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log.info('Interface is receiving multicast groups %s' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def ztest_igmp_exclude_empty_src_list_functionality(self):
        '''This test is sending join with source list A,B,C and exclude D,F,G'''
        '''Disabling this test case since scapy IGMP doesn't work with empty src list'''
        df = defer.Deferred()
        def igmp_exclude_empty_src_list_functionality():
              self.igmp_exclude_empty_src_list_functionality()
              df.callback(0)
        reactor.callLater(0, igmp_exclude_empty_src_list_functionality)
        return df

    def igmp_join_sourceip_0_0_0_0_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log.info('Interface is receiving from multicast groups %s when we sent join with source IP  is 0.0.0.0' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_join_sourceip_0_0_0_0_functionality(self):
        '''This test is sending join with source list A,B,C and exclude D,F,G with source IP as 0.0.0.0'''
        df = defer.Deferred()
        def igmp_join_sourceip_0_0_0_0_functionality():
              self.igmp_join_sourceip_0_0_0_0_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_join_sourceip_0_0_0_0_functionality)
        return df

    def igmp_invalid_join_packet_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving data from multicast groups %s when we sent invalid join packet ' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalid_join_packet_functionality(self):
        '''This test is sending invalid join with source list A,B,C and exclude D,F,G with multicast group as 255.255.255.255'''
        df = defer.Deferred()
        def igmp_invalid_join_packet_functionality():
              self.igmp_invalid_join_packet_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_invalid_join_packet_functionality)
        return df

    def igmp_join_data_receiving_during_subscriber_link_down_up_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log.info('Interface is receiving data from multicast groups, before bringing it down self.V_INF1=%s  ' %self.V_INF1)
        os.system('ifconfig '+self.V_INF1+' down')
        log.info(' the self.V_INF1 %s is down now  ' %self.V_INF1)
        os.system('ifconfig '+self.V_INF1)
        time.sleep(10)
        #target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        #assert target1==1, 'EXPECTED FAILURE'
        #log.info('Interface is not receiving from multicast groups %s when we shutdown the subscriber interface ' %groups2)
        os.system('ifconfig '+self.V_INF1+' up')
        os.system('ifconfig '+self.V_INF1)
        log.info(' the self.V_INF1 %s is up now  ' %self.V_INF1)
        #target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        #assert target1==0, 'EXPECTED FAILURE'
        #log.info('Interface is not receiving from multicast groups %s when we shutdown the subscriber interface ' %groups2)
        target1 = self.igmp_recv_task(self.V_INF1, groups2, join_state1)
        log.info('Interface is receiving data from multicast groups %s when we bring up interface  ' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()


    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_join_data_receiving_during_subscriber_link_down_up_functionality(self):
        '''This test is sending join with source list A,B,C and exclude D,F,G with valid multicast group during receiving data, shutdown the data receiving port  '''
        df = defer.Deferred()
        def igmp_join_data_receiving_during_subscriber_link_down_up_functionality():
            self.igmp_join_data_receiving_during_subscriber_link_down_up_functionality(df = df)
            df.callback(0)
        reactor.callLater(0, igmp_join_data_receiving_during_subscriber_link_down_up_functionality)
        return df


    def igmp_invalidClassDIP_join_packet_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving data from multicast groups %s when we send invalid join packet ' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalidClassDIP_join_packet_functionality(self):
        '''This test is sending invalid join with source list A,B,C and exclude D,F,G with multicast group as 239.255.255.255'''
        df = defer.Deferred()
        def igmp_invalidClassDIP_join_packet_functionality():
              self.igmp_invalidClassDIP_join_packet_functionality(df = df)
              df.callback(0)
        reactor.callLater(0, igmp_invalidClassDIP_join_packet_functionality)
        return df

    def igmp_invalidClassDIP_as_srclistIP_join_packet_functionality(self, df = None):
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
        igmpStateRecv1 = IGMPTestState(groups = groups2, df = df)
        mcastTraffic1 = McastTraffic(groups2, iface= 'veth2', dst_mac = dst_mac,
                                     src_ip = src_ip, cb = self.send_mcast_cb, arg = igmpState1)
        mcastTraffic1.start()
        join_state1 = IGMPTestState(groups = groups2)
        target1 = self.igmp_not_recv_task(self.V_INF1, groups2, join_state1)
        assert target1==1, 'EXPECTED FAILURE'
        log.info('Interface is not receiving data from multicast groups %s when we send invalid join packet ' %groups2)
        mcastTraffic1.stop()
        self.onos_ctrl.deactivate()

    @deferred(timeout=MCAST_TRAFFIC_TIMEOUT+20)
    def test_igmp_invalidClassDIP_as_srclistIP_join_packet_functionality(self):
        '''This test is sending invalid join with source list A,B,C and exclude D,F,G with source list as  239.5.5.5'''
        df = defer.Deferred()
        def igmp_invalidClassDIP_as_srclistIP_join_packet_functionality():
            self.igmp_invalidClassDIP_as_srclistIP_join_packet_functionality(df = df)
            df.callback(0)
        reactor.callLater(0, igmp_invalidClassDIP_as_srclistIP_join_packet_functionality)
        return df 

    def send_igmp_join_listeningQuery(self, groups, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
         self.onos_ssm_table_load(groups, src_list)
         igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, 
                       max_resp_code=30,
                       gaddr=self.IP_DST)
         for g in groups:
               gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
               gr.sources = src_list
               igmp.grps.append(gr)
         if ip_pkt is None:
               ip_pkt = self.igmp_eth/self.igmp_ip
         pkt = ip_pkt/igmp
         IGMPv3.fixup(pkt)
         resp = srp1(pkt, iface=iface)
         resp[0].summary()
         if delay != 0:
             time.sleep(delay)
