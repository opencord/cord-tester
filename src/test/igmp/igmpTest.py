import unittest
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from scapy.all import *
import time
import os, sys
CORD_TEST_UTILS = 'utils'
test_root = os.getenv('CORD_TEST_ROOT') or './'
sys.path.append(test_root + CORD_TEST_UTILS)
from IGMP import *

class IGMPTestState:

      def __init__(self, groups = [], df = None, state = 0):
            self.df = df
            self.state = state
            self.counter = 0
            self.groups = groups
            self.group_map = {} ##create a send/recv count map
            for g in groups:
                self.group_map[g] = [0, 0]

      def update(self, group, tx = 0, rx = 0):
            index = 0 if rx == 0 else 1
            v = tx if rx == 0 else rx
            if self.group_map.has_key(group):
                self.group_map[group][index] += v

      def update_state(self):
          self.state = self.state ^ 1
          self.counter += 1

class igmp_exchange(unittest.TestCase):
    
    def igmp_verify(self, igmpState):
        ## check if the send is received for the groups
        for g in igmpState.groups:
            tx = igmpState.group_map[g][0]
            rx = igmpState.group_map[g][1]
            assert_greater(tx, 0)
            assert_equal(tx, rx)
        print 'IGMP test verification success'

    def igmp_send(self, igmpState, iface = 'veth2'):
        dst_mac = '01:00:5e:00:01:01'
        src_mac = '02:88:b4:e4:90:77'
        src_ip = '1.2.3.4'
        eth = Ether(dst = dst_mac, src = src_mac)
        data = repr(time.time())
        for g in igmpState.groups:
            ip = IP(dst = g, src = src_ip)
            sendp(eth/ip/data, iface=iface)
            igmpState.update(g, tx = 1)

        ##done sending. Bounce the states
        igmpState.update_state()
        return 0

    def igmp_recv(self, igmpState, iface = 'veth0'):
        for g in igmpState.groups:
            igmpState.update(g, rx = 1)
        ##done receiving. Bounce the state back to send
        igmpState.update_state()
        return 0

    def send_igmp_join(self, igmpState, iface = 'veth0'):
        src_list = ['1.2.3.4']
        for g in igmpState.groups:
            igmp = IGMP(mtype = IGMPV3_REPORT, 
                        group = g,
                        rtype = IGMP_EXCLUDE,
                        src_list = src_list)
            sendp(igmp.scapify(), iface = iface)

    @deferred(timeout=10)
    def test_igmp_sendrecv(self):
        groups = ['224.0.1.1', '225.0.0.1']
        def igmp_srp_task(stateObject):
            if stateObject.state == 0:
                result = self.igmp_send(stateObject)
            else:
                result = self.igmp_recv(stateObject)

            if stateObject.counter < 20:
                reactor.callLater(0, igmp_srp_task, stateObject)
            else:
                self.igmp_verify(stateObject)
                stateObject.df.callback(0)

        df = defer.Deferred()
        igmpState = IGMPTestState(groups = groups, df = df)
        self.send_igmp_join(igmpState)
        reactor.callLater(0, igmp_srp_task, igmpState)
        return df

