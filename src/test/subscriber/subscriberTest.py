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
from Stats import Stats
from OnosCtrl import OnosCtrl
from DHCP import DHCPTest
from EapTLS import TLSAuthTest
from Channels import Channels
from subscriberDb import SubscriberDB
log.setLevel('INFO')

class Subscriber(Channels):

      STATS_RX = 0
      STATS_TX = 1
      STATS_JOIN = 2
      STATS_LEAVE = 3
      SUBSCRIBER_SERVICES = 'DHCP IGMP TLS'
      def __init__(self, name = 'sub', service = SUBSCRIBER_SERVICES, num = 1, iface = 'veth0', iface_mcast = 'veth2', 
                   mcast_cb = None, loginType = 'wireless'):
            Channels.__init__(self, num, iface = iface, iface_mcast = iface_mcast, mcast_cb = mcast_cb)
            self.name = name
            self.service = service
            self.service_map = {}
            services = self.service.strip().split(' ')
            for s in services:
                  self.service_map[s] = True
            self.loginType = loginType
            ##start streaming channels
            self.join_map = {}
            ##accumulated join recv stats
            self.join_rx_stats = Stats()

      def has_service(self, service):
            if self.service_map.has_key(service):
                  return self.service_map[service]
            if self.service_map.has_key(service.upper()):
                  return self.service_map[service.upper()]
            return False

      def channel_join_update(self, chan, join_time):
            self.join_map[chan] = ( Stats(), Stats(), Stats(), Stats() )
            self.channel_update(chan, self.STATS_JOIN, 1, t = join_time)

      def channel_join(self, chan = 0, delay = 2):
            '''Join a channel and create a send/recv stats map'''
            if self.join_map.has_key(chan):
                  del self.join_map[chan]
            self.delay = delay
            chan, join_time = self.join(chan)
            self.channel_join_update(chan, join_time)
            return chan

      def channel_join_next(self, delay = 2):
            '''Joins the next channel leaving the last channel'''
            if self.last_chan:
                  if self.join_map.has_key(self.last_chan):
                        del self.join_map[self.last_chan]
            self.delay = delay
            chan, join_time = self.join_next()
            self.channel_join_update(chan, join_time)
            return chan

      def channel_jump(self, delay = 2):
            '''Jumps randomly to the next channel leaving the last channel'''
            if self.last_chan is not None:
                  if self.join_map.has_key(self.last_chan):
                        del self.join_map[self.last_chan]
            self.delay = delay
            chan, join_time = self.jump()
            self.channel_join_update(chan, join_time)
            return chan

      def channel_leave(self, chan = 0):
            if self.join_map.has_key(chan):
                  del self.join_map[chan]
            self.leave(chan)

      def channel_update(self, chan, stats_type, packets, t=0):
            if type(chan) == type(0):
                  chan_list = (chan,)
            else:
                  chan_list = chan
            for c in chan_list: 
                  if self.join_map.has_key(c):
                        self.join_map[c][stats_type].update(packets = packets, t = t)

      def channel_receive(self, chan, cb = None, count = 1):
            self.recv(chan, cb = cb, count = count)

class subscriber_exchange(unittest.TestCase):

      apps = [ 'org.onosproject.aaa', 'org.onosproject.dhcp' ]

      dhcp_server_config = {
        "ip": "10.1.11.50",
        "mac": "ca:fe:ca:fe:ca:fe",
        "subnet": "255.255.252.0",
        "broadcast": "10.1.11.255",
        "router": "10.1.8.1",
        "domain": "8.8.8.8",
        "ttl": "63",
        "delay": "2",
        "startip": "10.1.11.51",
        "endip": "10.1.11.100"
      }

      def setUp(self):
          ''' Activate the dhcp and igmp apps'''
          for app in self.apps:
              onos_ctrl = OnosCtrl(app)
              status, _ = onos_ctrl.activate()
              assert_equal(status, True)
              time.sleep(2)

      def teardown(self):
          '''Deactivate the dhcp app'''
          for app in self.apps:
              onos_ctrl = OnosCtrl(app)
              onos_ctrl.deactivate()

      def onos_aaa_load(self):
            aaa_dict = {'apps' : { 'org.onosproject.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password', 
                                                                       'radiusIp': '172.17.0.2' } } } }
            radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
            aaa_dict['apps']['org.onosproject.aaa']['AAA']['radiusIp'] = radius_ip
            onos_ctrl = OnosCtrl('org.onosproject.aaa')
            onos_ctrl.deactivate()
            time.sleep(2)
            onos_ctrl.activate()
            time.sleep(2)
            self.onos_load_config('org.onosproject.aaa', aaa_dict)

      def onos_dhcp_table_load(self, config = None):
          dhcp_dict = {'apps' : { 'org.onosproject.dhcp' : { 'dhcp' : copy.copy(self.dhcp_server_config) } } }
          dhcp_config = dhcp_dict['apps']['org.onosproject.dhcp']['dhcp']
          if config:
              for k in config.keys():
                  if dhcp_config.has_key(k):
                      dhcp_config[k] = config[k]
          self.onos_load_config('org.onosproject.dhcp', dhcp_dict)

      def onos_load_config(self, app, config):
          onos_ctrl = OnosCtrl(app)
          status, code = onos_ctrl.config(config)
          if status is False:
             log.info('JSON config request for app %s returned status %d' %(app, code))
             assert_equal(status, True)
          time.sleep(2)

      def dhcp_sndrcv(self, update_seed = False):
            cip, sip = self.dhcp.discover(update_seed = update_seed)
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
            log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, self.dhcp.get_mac(cip)[0]))
            return cip,sip

      def dhcp_request(self, seed_ip = '10.10.10.1', iface = 'veth0'):
            config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                      'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                      'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
            self.onos_dhcp_table_load(config)
            self.dhcp = DHCPTest(seed_ip = seed_ip, iface = iface)
            cip, sip = self.dhcp_sndrcv()
            return cip, sip

      def recv_channel_cb(self, pkt):
            ##First verify that we have received the packet for the joined instance
            chan = self.subscriber.caddr(pkt[IP].dst)
            assert_equal(chan in self.subscriber.join_map.keys(), True)
            recv_time = monotonic.monotonic() * 1000000
            join_time = self.subscriber.join_map[chan][self.subscriber.STATS_JOIN].start
            delta = recv_time - join_time
            self.subscriber.join_rx_stats.update(packets=1, t = delta, usecs = True)
            self.subscriber.channel_update(chan, self.subscriber.STATS_RX, 1, t = delta)
            log.info('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))
            self.test_status = True

      def subscriber_load(self, create = True, num = 10):
            '''Load the subscriber from the database'''
            self.subscriber_db = SubscriberDB(create = create)
            if create is True:
                  self.subscriber_db.generate(num)
            self.subscriber_info = self.subscriber_db.read(num)
            self.subscriber_list = []
            for info in self.subscriber_info:
                  self.subscriber_list.append(Subscriber(info['Name'], info['Service']))

      def test_subscriber_join_recv( self, chan = 0):
          """Test 1 subscriber join and receive""" 
          self.test_status = False
          self.num_subscribers = 10
          self.subscriber_load(create = True, num = self.num_subscribers)
          for subscriber in self.subscriber_list:
                self.subscriber = subscriber
                self.subscriber.start()
                log.info('Testing subscriber %s for %s' %(subscriber.name, subscriber.service))
                if self.subscriber.has_service('TLS'):
                      self.onos_aaa_load()
                      time.sleep(2)
                      tls = TLSAuthTest()
                      tls.runTest()
                      self.test_status = True
                if self.subscriber.has_service('DHCP'):
                      cip, sip = self.dhcp_request(iface = self.subscriber.iface)
                      log.info('Got client ip %s from server %s' %(cip, sip))
                      self.subscriber.src_list = [cip]
                      self.test_status = True
                if self.subscriber.has_service('IGMP'):
                      for i in range(5):
                            log.info('Joining channel %d' %chan)
                            self.subscriber.channel_join(chan, delay = 0)
                            self.subscriber.channel_receive(chan, cb = self.recv_channel_cb, count = 1)
                            log.info('Leaving channel %d' %chan)
                            self.subscriber.channel_leave(chan)
                            time.sleep(3)
                      log.info('Join RX stats %s' %self.subscriber.join_rx_stats)
                self.subscriber.stop()
          ##Terminate the tests on success
          assert_equal(self.test_status, True)


      def test_subscriber_join_jump(self):
          """Test 1 subscriber join and receive""" 
          self.test_status = False
          self.subscriber = Subscriber(50)
          self.subscriber.start()
          self.onos_aaa_load()
          #tls = TLSAuthTest()
          #tls.runTest()
          ##Next get dhcp
          cip, sip = self.dhcp_request(seed_ip = '10.10.200.1', iface = self.subscriber.iface)
          log.info('Got client ip %s from server %s' %(cip, sip))
          self.subscriber.src_list = [cip]
          for i in range(50):
                log.info('Jumping channel')
                chan = self.subscriber.channel_jump(delay=0)
                self.subscriber.channel_receive(chan, cb = self.recv_channel_cb, count = 1)
                log.info('Verified receive for channel %d' %chan)
                time.sleep(3)

          log.info('Join RX stats %s' %self.subscriber.join_rx_stats)
          self.subscriber.stop()
          ##Terminate the tests on success
          assert_equal(self.test_status, True)

      def test_subscriber_join_next(self):
          """Test subscriber join next for channels"""
          self.test_status = False
          self.subscriber = Subscriber(10)
          self.subscriber.start()
          self.onos_aaa_load()
          #tls = TLSAuthTest()
          #tls.runTest()
          ##Next get dhcp
          cip, sip = self.dhcp_request(seed_ip = '10.10.150.1', iface = self.subscriber.iface)
          log.info('Got client ip %s from server %s' %(cip, sip))
          self.subscriber.src_list = [cip]
          for i in range(10):
                if i:
                      chan = self.subscriber.channel_join_next(delay=0)
                else:
                      chan = self.subscriber.channel_join(i, delay=0)
                log.info('Joined next channel %d' %chan)
                self.subscriber.channel_receive(chan, cb = self.recv_channel_cb, count=1)
                log.info('Verified receive for channel %d' %chan)
                time.sleep(3)

          log.info('Join Next RX stats %s' %self.subscriber.join_rx_stats)
          self.subscriber.stop()
          ##Terminate the tests on success
          assert_equal(self.test_status, True)
