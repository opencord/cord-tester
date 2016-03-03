import threading
import sys
import os
import time
import monotonic
from scapy.all import *

class McastTraffic(threading.Thread):

    dst_mac = '01:00:5e:00:01:01'
    src_mac = '02:88:b4:e4:90:77'
    src_ip = '1.2.3.4'
    SEND_STATE = 1
    RECV_STATE = 2
    def __init__(self, addrs, iface = 'eth0', cb = None, arg = None):
        threading.Thread.__init__(self)
        self.addrs = addrs
        self.iface = iface
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

    
