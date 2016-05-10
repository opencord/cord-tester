#!/usr/bin/env python
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
from scapy.all import *

class McastTraffic(threading.Thread):
    DST_MAC_DEFAULT = '01:00:5e:00:01:01'
    SRC_MAC_DEFAULT = '02:88:b4:e4:90:77'
    SRC_IP_DEFAULT = '1.2.3.4'
    SEND_STATE = 1
    RECV_STATE = 2

    def __init__(self, addrs, iface = 'eth0', dst_mac = DST_MAC_DEFAULT, src_mac = SRC_MAC_DEFAULT,
                 src_ip = SRC_IP_DEFAULT, cb = None, arg = None):
        threading.Thread.__init__(self)
        self.addrs = addrs
        self.iface = iface
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.cb = cb
        self.arg = arg
        self.state = self.SEND_STATE | self.RECV_STATE

    def run(self):
        eth = Ether(dst = self.dst_mac, src = self.src_mac)
        while self.state & self.SEND_STATE:
            for addr in self.addrs:
                #data = repr(time.time())
                data = repr(monotonic.monotonic())
                ip = IP(dst = addr, src = self.src_ip)
                sendp(eth/ip/data, iface = self.iface)
            if self.cb:
                self.cb(self.arg)

    def stop(self):
        self.state = 0

    def stopReceives(self):
        self.state &= ~self.RECV_STATE

    def stopSends(self):
        self.state &= ~self.SEND_STATE

    def isRecvStopped(self):
        return False if self.state & self.RECV_STATE else True

    def isSendStopped(self):
        return False if self.state & self.SEND_STATE else True

