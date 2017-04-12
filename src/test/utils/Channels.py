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
import threading
import sys
import os
import time
import monotonic
import random
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from McastTraffic import *
from IGMP import *
from OnosCtrl import OnosCtrl
from CordTestUtils import log_test
from nose.tools import *
log_test.setLevel('DEBUG')

conf.verb = 0

class IgmpChannel:

    IGMP_DST_MAC = "01:00:5e:00:01:01"
    IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
    IP_SRC = '1.2.3.4'
    IP_DST = '224.0.1.1'
    igmp_eth = Ether(dst = IGMP_DST_MAC, src = IGMP_SRC_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST, src = IP_SRC)
    ssm_list = []

    def __init__(self, iface = 'veth0', ssm_list = [], src_list = ['1.2.3.4'], delay = 2,controller=None):
	self.controller=controller
        self.iface = iface
        self.ssm_list += ssm_list
        self.src_list = src_list
        self.delay = delay
        self.onos_ctrl = OnosCtrl('org.onosproject.igmp',controller=self.controller)
        self.onos_ctrl.activate()

    def igmp_load_ssm_config(self, ssm_list = []):
        if not ssm_list:
            ssm_list = self.ssm_list
        self.ssm_table_load(ssm_list)

    def igmp_join(self, groups):
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr='224.0.1.1')
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=g)
              gr.sources = self.src_list
              igmp.grps.append(gr)

        pkt = self.igmp_eth/self.igmp_ip/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface=self.iface)
        if self.delay != 0:
            time.sleep(self.delay)

    def igmp_leave(self, groups):
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr='224.0.1.1')
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
              gr.sources = self.src_list
              igmp.grps.append(gr)

        pkt = self.igmp_eth/self.igmp_ip/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface = self.iface)
        if self.delay != 0:
            time.sleep(self.delay)

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config,controller=self.controller)
        if status is False:
            log_test.info('JSON config request returned status %d' %code)
        time.sleep(2)

    def ssm_table_load(self, groups):
          ssm_dict = {'apps' : { 'org.onosproject.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.onosproject.igmp']['ssmTranslate']
          for g in groups:
                for s in self.src_list:
                      d = {}
                      d['source'] = s
                      d['group'] = g
                      ssm_xlate_list.append(d)
          self.onos_load_config(ssm_dict)

    def cord_port_table_load(self, cord_port_map):
          cord_group_dict = {'apps' : { 'org.ciena.cordigmp' : { 'cordIgmpTranslate' : [] } } }
          cord_group_xlate_list = cord_group_dict['apps']['org.ciena.cordigmp']['cordIgmpTranslate']
          for group, ports in cord_port_map.items():
              d = {}
              d['group'] = group
              d['inputPort'] = ports[0]
              d['outputPort'] = ports[1]
              cord_group_xlate_list.append(d)
          self.onos_load_config(cord_group_dict)

class Channels(IgmpChannel):
    Stopped = 0
    Started = 1
    Idle = 0
    Joined = 1
    def __init__(self, num, channel_start = 0, iface = 'veth0', iface_mcast = 'veth2', mcast_cb = None):
        self.num = num
        self.channel_start = channel_start
        self.channels = self.generate(self.num, self.channel_start)
        self.group_channel_map = {}
        #assert_equal(len(self.channels), self.num)
        for i in range(self.num):
            self.group_channel_map[self.channels[i]] = i
        self.state = self.Stopped
        self.streams = None
        self.channel_states = {}
        self.last_chan = None
        self.iface_mcast = iface_mcast
        self.mcast_cb = mcast_cb
        for c in range(self.num):
            self.channel_states[c] = [self.Idle]
        IgmpChannel.__init__(self, ssm_list = self.channels, iface=iface)

    def generate(self, num, channel_start = 0):
        start = (225 << 24) | ( ( (channel_start >> 16) & 0xff) << 16 ) | \
            ( ( (channel_start >> 8) & 0xff ) << 8 ) | (channel_start) & 0xff
        start += channel_start/256 + 1
        end = start + num
        group_addrs = []
        count = 0
        while count != num:
            for i in range(start, end):
                if i&255:
                    g = '%s.%s.%s.%s' %((i>>24) &0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
                    log_test.debug('Adding group %s' %g)
                    group_addrs.append(g)
                    count += 1
            start = end
            end = start + 1
        return group_addrs

    def start(self):
        if self.state == self.Stopped:
            if self.streams:
                self.streams.stop()
            self.streams = McastTraffic(self.channels, iface=self.iface_mcast, cb = self.mcast_cb)
            self.streams.start()
            self.state = self.Started

    def join(self, chan = None):
        if chan is None:
            chan = random.randint(0, self.num)
        else:
            if chan >= self.num:
                chan = 0

        if self.get_state(chan) == self.Joined:
            return chan, 0

        groups = [self.channels[chan]]
        join_start = monotonic.monotonic()
        self.igmp_join(groups)
        self.set_state(chan, self.Joined)
        self.last_chan = chan
        return chan, join_start

    def leave(self, chan):
        if chan is None:
            chan = self.last_chan
        if chan is None or chan >= self.num:
            return False
        if self.get_state(chan) != self.Joined:
            return False
        groups = [self.channels[chan]]
        self.igmp_leave(groups)
        self.set_state(chan, self.Idle)
        if chan == self.last_chan:
            self.last_chan = None
        return True

    def join_next(self, chan = None):
        if chan is None:
            chan = self.last_chan
            if chan is None:
                return None
            leave = chan
            join = chan+1
        else:
            leave = chan - 1
            join = chan

        if join >= self.num:
            join = 0

        if leave >= 0 and leave != join:
            self.leave(leave)

        return self.join(join)

    def jump(self):
        chan = self.last_chan
        if chan is not None:
            self.leave(chan)
            s_next = chan
        else:
            s_next = 0
        if self.num - s_next < 2:
            s_next = 0
        chan = random.randint(s_next, self.num)
        return self.join(chan)

    def gaddr(self, chan):
        '''Return the group address for a channel'''
        if chan >= self.num:
            return None
        return self.channels[chan]

    def caddr(self, group):
        '''Return a channel given a group addr'''
        if self.group_channel_map.has_key(group):
            return self.group_channel_map[group]
        return None

    def recv_cb(self, pkt):
        '''Default channel receive callback'''
        log_test.debug('Received packet from source %s, destination %s' %(pkt[IP].src, pkt[IP].dst))
        send_time = float(pkt[IP].payload.load)
        recv_time = monotonic.monotonic()
        log_test.debug('Packet received in %.3f usecs' %(recv_time - send_time))

    def recv(self, chan, cb = None, count = 1, timeout = 5):
        if chan is None:
            return None
        if type(chan) == type([]) or type(chan) == type(()):
            channel_list=filter(lambda c: c < self.num, chan)
            groups = map(lambda c: self.gaddr(c), channel_list)
        else:
            groups = (self.gaddr(chan),)
        if cb is None:
            cb = self.recv_cb
        return sniff(prn = cb, count=count, timeout = timeout,
                     lfilter = lambda p: IP in p and p[IP].dst in groups, iface = self.iface)

    def stop(self):
        if self.streams:
            self.streams.stop()
        self.state = self.Stopped

    def get_state(self, chan):
        return self.channel_states[chan][0]

    def set_state(self, chan, state):
        self.channel_states[chan][0] = state

if __name__ == '__main__':
    num = 5
    start = 0
    ssm_list = []
    for i in xrange(2):
        channels = Channels(num, start)
        ssm_list += channels.channels
        start += num
    igmpChannel = IgmpChannel()
    igmpChannel.igmp_load_ssm_config(ssm_list)
    channels.start()
    for i in range(num):
        channels.join(i)
    for i in range(num):
        channels.recv(i)
    for i in range(num):
        channels.leave(i)
    channels.stop()
