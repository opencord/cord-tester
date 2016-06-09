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
from Channels import Channels, IgmpChannel
from subscriberDb import SubscriberDB
from threadPool import ThreadPool
from portmaps import g_subscriber_port_map
from OltConfig import *
from CordContainer import *
import copy
log.setLevel('INFO')
DEFAULT_NO_CHANNELS = 1

class Subscriber(Channels):
      PORT_TX_DEFAULT = 2
      PORT_RX_DEFAULT = 1
      INTF_TX_DEFAULT = 'veth2'
      INTF_RX_DEFAULT = 'veth0'
      STATS_RX = 0
      STATS_TX = 1
      STATS_JOIN = 2
      STATS_LEAVE = 3
      SUBSCRIBER_SERVICES = 'DHCP IGMP TLS'


      def __init__(self, name = 'sub', service = SUBSCRIBER_SERVICES, port_map = None,
                   num = 1, channel_start = 0,
                   tx_port = PORT_TX_DEFAULT, rx_port = PORT_RX_DEFAULT,
                   iface = INTF_RX_DEFAULT, iface_mcast = INTF_TX_DEFAULT,
                   mcast_cb = None, loginType = 'wireless'):
            self.tx_port = tx_port
            self.rx_port = rx_port
            self.port_map = port_map or g_subscriber_port_map
            try:
                  self.tx_intf = self.port_map[tx_port]
                  self.rx_intf = self.port_map[rx_port]
            except:
                  self.tx_intf = self.port_map[self.PORT_TX_DEFAULT]
                  self.rx_intf = self.port_map[self.PORT_RX_DEFAULT]

            Channels.__init__(self, num, channel_start = channel_start,
                              iface = self.rx_intf, iface_mcast = self.tx_intf, mcast_cb = mcast_cb)
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
            log.info("Jumps randomly to the next channel leaving the last channel")
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
            log.info('Subscriber %s receiving from group %s, channel %d' %(self.name, self.gaddr(chan), chan))
            self.recv(chan, cb = cb, count = count)

      def recv_channel_cb(self, pkt):
            ##First verify that we have received the packet for the joined instance
            log.debug('Packet received for group %s, subscriber %s' %(pkt[IP].dst, self.name))
            chan = self.caddr(pkt[IP].dst)
            assert_equal(chan in self.join_map.keys(), True)
            recv_time = monotonic.monotonic() * 1000000
            join_time = self.join_map[chan][self.STATS_JOIN].start
            delta = recv_time - join_time
            self.join_rx_stats.update(packets=1, t = delta, usecs = True)
            self.channel_update(chan, self.STATS_RX, 1, t = delta)
            log.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))

class subscriber_pool:

      def __init__(self, subscriber, test_cbs, test_status):
            self.subscriber = subscriber
            self.test_cbs = test_cbs
            self.test_status = test_status

      def pool_cb(self):
            for cb in self.test_cbs:
                  if cb:
                        self.test_status = cb(self.subscriber)
#                        cb(self.subscriber)
                        if self.test_status is not True:
                           log.info('This service is failed and other services will not run for this subscriber')
                           break
            log.info('This Subscriber is tested for multiple service elgibility ')
            self.test_status = True

class subscriber_exchange(unittest.TestCase):

      apps = [ 'org.onosproject.aaa', 'org.onosproject.dhcp' ]

      dhcp_app = 'org.onosproject.dhcp'

      olt_apps = [ 'org.onosproject.igmp', 'org.onosproject.cordmcast' ]
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

      aaa_loaded = False
      INTF_TX_DEFAULT = 'veth2'
      INTF_RX_DEFAULT = 'veth0'
      SUBSCRIBER_TIMEOUT = 20

      CLIENT_CERT = """-----BEGIN CERTIFICATE-----
MIICuDCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBizELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5h
IEluYy4xHjAcBgkqhkiG9w0BCQEWD2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMd
RXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwNjA2MjExMjI3WhcN
MTcwNjAxMjExMjI3WjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNV
BAoTCkNpZW5hIEluYy4xFzAVBgNVBAMUDnVzZXJAY2llbmEuY29tMR0wGwYJKoZI
hvcNAQkBFg51c2VyQGNpZW5hLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAwvXiSzb9LZ6c7uNziUfKvoHO7wu/uiFC5YUpXbmVGuGZizbVrny0xnR85Dfe
+9R4diansfDhIhzOUl1XjN3YDeSS9OeF5YWNNE8XDhlz2d3rVzaN6hIhdotBkUjg
rUewjTg5OFR31QEyG3v8xR3CLgiE9xQELjZbSA07pD79zuUCAwEAAaNPME0wEwYD
VR0lBAwwCgYIKwYBBQUHAwIwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5l
eGFtcGxlLmNvbS9leGFtcGxlX2NhLmNybDANBgkqhkiG9w0BAQUFAAOBgQDAjkrY
6tDChmKbvr8w6Du/t8vHjTCoCIocHTN0qzWOeb1YsAGX89+TrWIuO1dFyYd+Z0KC
PDKB5j/ygml9Na+AklSYAVJIjvlzXKZrOaPmhZqDufi+rXWti/utVqY4VMW2+HKC
nXp37qWeuFLGyR1519Y1d6F/5XzqmvbwURuEug==
-----END CERTIFICATE-----"""

      CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIDvTCCAqWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBizELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5h
IEluYy4xHjAcBgkqhkiG9w0BCQEWD2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMd
RXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwMzExMTg1MzM2WhcN
MTcwMzA2MTg1MzM2WjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNV
BAoTCkNpZW5hIEluYy4xFzAVBgNVBAMUDnVzZXJAY2llbmEuY29tMR0wGwYJKoZI
hvcNAQkBFg51c2VyQGNpZW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAOxemcBsPn9tZsCa5o2JA6sQDC7A6JgCNXXl2VFzKLNNvB9PS6D7ZBsQ
5An0zEDMNzi51q7lnrYg1XyiE4S8FzMGAFr94RlGMQJUbRD9V/oqszMX4k++iAOK
tIA1gr3x7Zi+0tkjVSVzXTmgNnhChAamdMsjYUG5+CY9WAicXyy+VEV3zTphZZDR
OjcjEp4m/TSXVPYPgYDXI40YZKX5BdvqykWtT/tIgZb48RS1NPyN/XkCYzl3bv21
qx7Mc0fcEbsJBIIRYTUkfxnsilcnmLxSYO+p+DZ9uBLBzcQt+4Rd5pLSfi21WM39
2Z2oOi3vs/OYAPAqgmi2JWOv3mePa/8CAwEAAaNPME0wEwYDVR0lBAwwCgYIKwYB
BQUHAwIwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5leGFtcGxlLmNvbS9l
eGFtcGxlX2NhLmNybDANBgkqhkiG9w0BAQUFAAOCAQEALBzMPDTIB6sLyPl0T6JV
MjOkyldAVhXWiQsTjaGQGJUUe1cmUJyZbUZEc13MygXMPOM4x7z6VpXGuq1c/Vxn
VzQ2fNnbJcIAHi/7G8W5/SQfPesIVDsHTEc4ZspPi5jlS/MVX3HOC+BDbOjdbwqP
RX0JEr+uOyhjO+lRxG8ilMRACoBUbw1eDuVDoEBgErSUC44pq5ioDw2xelc+Y6hQ
dmtYwfY0DbvwxHtA495frLyPcastDiT/zre7NL51MyUDPjjYjghNQEwvu66IKbQ3
T1tJBrgI7/WI+dqhKBFolKGKTDWIHsZXQvZ1snGu/FRYzg1l+R/jT8cRB9BDwhUt
yg==
-----END CERTIFICATE-----'''

      def setUp(self):
          '''Load the OLT config and activate relevant apps'''
          self.olt = OltConfig()
          self.port_map = self.olt.olt_port_map()
          ##if no olt config, fall back to ovs port map
          if not self.port_map:
                self.port_map = g_subscriber_port_map
          else:
                log.info('Using OLT Port configuration for test setup')
                log.info('Configuring CORD OLT access device information')
                OnosCtrl.cord_olt_config(self.olt.olt_device_data())
                self.activate_apps(self.olt_apps)

          self.activate_apps(self.apps)

      def teardown(self):
          '''Deactivate the dhcp app'''
          for app in self.apps:
              onos_ctrl = OnosCtrl(app)
              onos_ctrl.deactivate()
          log.info('Restarting the Radius container in the setup after running every subscriber test cases by default')
          rest = Container('cord-radius', 'cord-test/radius',)
          rest.restart('cord-radius','10')
          radius = Radius()
          radius_ip = radius.ip()
          print('Radius server is running with IP %s' %radius_ip)
          #os.system('ifconfig '+INTF_RX_DEFAULT+' up')


      def activate_apps(self, apps):
            for app in apps:
                  onos_ctrl = OnosCtrl(app)
                  status, _ = onos_ctrl.activate()
                  assert_equal(status, True)
                  time.sleep(2)

      def onos_aaa_load(self):
            if self.aaa_loaded:
                  return
            aaa_dict = {'apps' : { 'org.onosproject.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                       'radiusIp': '172.17.0.2' } } } }
            radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
            aaa_dict['apps']['org.onosproject.aaa']['AAA']['radiusIp'] = radius_ip
            self.onos_load_config('org.onosproject.aaa', aaa_dict)
            self.aaa_loaded = True

      def onos_dhcp_table_load(self, config = None):
          dhcp_dict = {'apps' : { 'org.onosproject.dhcp' : { 'dhcp' : copy.copy(self.dhcp_server_config) } } }
          dhcp_config = dhcp_dict['apps']['org.onosproject.dhcp']['dhcp']
          if config:
              for k in config.keys():
                  if dhcp_config.has_key(k):
                      dhcp_config[k] = config[k]
          self.onos_load_config('org.onosproject.dhcp', dhcp_dict)

      def send_recv(self, mac = None, update_seed = False, validate = True):
          cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
          if validate:
             assert_not_equal(cip, None)
             assert_not_equal(sip, None)
             log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, self.dhcp.get_mac(cip)[0]))
          return cip,sip

      def onos_load_config(self, app, config):
          status, code = OnosCtrl.config(config)
          if status is False:
             log.info('JSON config request for app %s returned status %d' %(app, code))
             assert_equal(status, True)
          time.sleep(2)

      def dhcp_sndrcv(self, dhcp, update_seed = False):
            cip, sip = dhcp.discover(update_seed = update_seed)
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
            log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, dhcp.get_mac(cip)[0]))
            return cip,sip

      def dhcp_request(self, subscriber, seed_ip = '10.10.10.1', update_seed = False):
            config = {'startip':'10.10.10.20', 'endip':'10.10.10.200',
                      'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                      'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
            self.onos_dhcp_table_load(config)
            dhcp = DHCPTest(seed_ip = seed_ip, iface = subscriber.iface)
            cip, sip = self.dhcp_sndrcv(dhcp, update_seed = update_seed)
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
            log.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))
            self.test_status = True

      def tls_verify(self, subscriber):
            if subscriber.has_service('TLS'):
                  time.sleep(2)
                  tls = TLSAuthTest()
                  log.info('Running subscriber %s tls auth test' %subscriber.name)
                  tls.runTest()
                  self.test_status = True
                  return self.test_status

      def dhcp_verify(self, subscriber):
            cip, sip = self.dhcp_request(subscriber, update_seed = True)
            log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
            subscriber.src_list = [cip]
            self.test_status = True
            return self.test_status

      def dhcp_jump_verify(self, subscriber):
          cip, sip = self.dhcp_request(subscriber, seed_ip = '10.10.200.1')
          log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
          subscriber.src_list = [cip]
          self.test_status = True
          return self.test_status

      def dhcp_next_verify(self, subscriber):
          cip, sip = self.dhcp_request(subscriber, seed_ip = '10.10.150.1')
          log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
          subscriber.src_list = [cip]
          self.test_status = True
          return self.test_status

      def igmp_verify(self, subscriber):
            chan = 0
            if subscriber.has_service('IGMP'):
                  for i in range(5):
                        log.info('Joining channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_join(chan, delay = 0)
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
                        log.info('Leaving channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_leave(chan)
                        time.sleep(3)
                        log.info('Interface %s Join RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name,subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status

      def igmp_verify_multiChannel(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for chan in range(DEFAULT_NO_CHANNELS):
                        log.info('Joining channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_join(chan, delay = 0)
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
                        log.info('Leaving channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_leave(chan)
                        time.sleep(3)
                        log.info('Interface %s Join RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name,subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status

      def igmp_jump_verify(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for i in xrange(subscriber.num):
                        log.info('Subscriber %s jumping channel' %subscriber.name)
                        chan = subscriber.channel_jump(delay=0)
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
                        log.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
                        time.sleep(3)
                  log.info('Interface %s Jump RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status

      def igmp_next_verify(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for i in xrange(subscriber.num):
                        if i:
                              chan = subscriber.channel_join_next(delay=0)
                        else:
                              chan = subscriber.channel_join(i, delay=0)
                        log.info('Joined next channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count=1)
                        log.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
                        time.sleep(3)
                  log.info('Interface %s Join Next RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status

      def generate_port_list(self, subscribers, channels):
            port_list = []
            for i in xrange(subscribers):
                  if channels > 1:
                        rx_port = 2*i+1
                        tx_port = 2*i+2
                  else:
                        rx_port = Subscriber.PORT_RX_DEFAULT
                        tx_port = Subscriber.PORT_TX_DEFAULT
                  port_list.append((tx_port, rx_port))
            return port_list

      def subscriber_load(self, create = True, num = 10, num_channels = 1, channel_start = 0, port_list = []):
            '''Load the subscriber from the database'''
            self.subscriber_db = SubscriberDB(create = create)
            if create is True:
                  self.subscriber_db.generate(num)
            self.subscriber_info = self.subscriber_db.read(num)
            self.subscriber_list = []
            if not port_list:
                  port_list = self.generate_port_list(num, num_channels)

            index = 0
            for info in self.subscriber_info:
                  self.subscriber_list.append(Subscriber(name=info['Name'],
                                                         service=info['Service'],
                                                         port_map = self.port_map,
                                                         num=num_channels,
                                                         channel_start = channel_start,
                                                         tx_port = port_list[index][0],
                                                         rx_port = port_list[index][1]))
                  if num_channels > 1:
                        channel_start += num_channels
                  index += 1

            #load the ssm list for all subscriber channels
            igmpChannel = IgmpChannel()
            ssm_groups = map(lambda sub: sub.channels, self.subscriber_list)
            ssm_list = reduce(lambda ssm1, ssm2: ssm1+ssm2, ssm_groups)
            igmpChannel.igmp_load_ssm_config(ssm_list)
            #load the subscriber to mcast port map for cord
            cord_port_map = {}
            for sub in self.subscriber_list:
                  for chan in sub.channels:
                        cord_port_map[chan] = (sub.tx_port, sub.rx_port)

            igmpChannel.cord_port_table_load(cord_port_map)

      def subscriber_join_verify( self, num_subscribers = 10, num_channels = 1,
                                  channel_start = 0, cbs = None, port_list = [], negative_subscriber_auth = None):
          self.test_status = False
          self.num_subscribers = num_subscribers
          self.sub_loop_count =  num_subscribers
          self.subscriber_load(create = True, num = num_subscribers,
                               num_channels = num_channels, channel_start = channel_start, port_list = port_list)
          self.onos_aaa_load()
          self.thread_pool = ThreadPool(min(100, self.num_subscribers), queue_size=1, wait_timeout=1)

          if cbs and negative_subscriber_auth is None:
                cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify)
          cbs_negative = cbs
          for subscriber in self.subscriber_list:
                subscriber.start()
                if negative_subscriber_auth is 'half' and self.sub_loop_count%2 is not 0:
                   cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify)
                elif negative_subscriber_auth is 'onethird' and self.sub_loop_count%3 is not 0:
                   cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify)
                else:
                   cbs = cbs_negative
                self.sub_loop_count = self.sub_loop_count - 1
                pool_object = subscriber_pool(subscriber, cbs, self.test_status)
                self.thread_pool.addTask(pool_object.pool_cb)
          self.thread_pool.cleanUpThreads()
          for subscriber in self.subscriber_list:
                subscriber.stop()
          return self.test_status

      def tls_invalid_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT_INVALID)
             tls.runTest()
             if tls.failTest == True:
                self.test_status = False
             return self.test_status

      def tls_no_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = '')
             tls.runTest()
             if tls.failTest == True:
                self.test_status = False
             return self.test_status

      def tls_self_signed_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT)
             tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status

      def tls_Nsubscribers_use_same_valid_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             num_users = 3
             for i in xrange(num_users):
                 tls = TLSAuthTest(intf = 'veth{}'.format(i*2))
                 tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status

      def dhcp_discover_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
             time.sleep(2)
             log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
             t1 = self.subscriber_dhcp_1release()
             self.test_status = True
             return self.test_status

      def subscriber_dhcp_1release(self, iface = INTF_RX_DEFAULT):
             config = {'startip':'10.10.100.20', 'endip':'10.10.100.21',
                       'ip':'10.10.100.2', 'mac': "ca:fe:ca:fe:8a:fe",
                       'subnet': '255.255.255.0', 'broadcast':'10.10.100.255', 'router':'10.10.100.1'}
             self.onos_dhcp_table_load(config)
             self.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = iface)
             cip, sip = self.send_recv()
             log.info('Releasing ip %s to server %s' %(cip, sip))
             assert_equal(self.dhcp.release(cip), True)
             log.info('Triggering DHCP discover again after release')
             cip2, sip2 = self.send_recv(update_seed = True)
             log.info('Verifying released IP was given back on rediscover')
             assert_equal(cip, cip2)
             log.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
             assert_equal(self.dhcp.release(cip2), True)


      def dhcp_client_reboot_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_request_after_reboot()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_client_request_after_reboot(self, iface = INTF_RX_DEFAULT):
          #''' Client sends DHCP Request after reboot.'''

          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )

          log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")

          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)

          else:
                new_cip, new_sip = self.dhcp.only_request(cip, mac)
                if new_cip == None:
                        log.info("Got DHCP server NAK.")
                os.system('ifconfig '+iface+' down')
                log.info('Client goes down.')
                log.info('Delay for 5 seconds.')

                time.sleep(5)

                os.system('ifconfig '+iface+' up')
                log.info('Client is up now.')

                new_cip, new_sip = self.dhcp.only_request(cip, mac)
                if new_cip == None:
                        log.info("Got DHCP server NAK.")
                        assert_not_equal(new_cip, None)
                elif new_cip != None:
                        log.info("Got DHCP ACK.")


      def dhcp_client_renew_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_renew_time()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_client_renew_time(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac , lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )

          log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          elif cip and sip and mac:
                log.info("Triggering DHCP Request.")
                new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
                if new_cip and new_sip and lval:
                        log.info("Client 's Renewal time is :%s",lval)
                        log.info("Generating delay till renewal time.")
                        time.sleep(lval)
                        log.info("Client Sending Unicast DHCP request.")
                        latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac, unicast = True)
                        if latest_cip and latest_sip:
                                log.info("Got DHCP Ack. Lease Renewed for ip %s and mac %s from server %s." %
                                                (latest_cip, mac, latest_sip) )

                        elif latest_cip == None:
                                log.info("Got DHCP NAK. Lease not renewed.")
                elif new_cip == None or new_sip == None or lval == None:
                        log.info("Got DHCP NAK.")


      def dhcp_server_reboot_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_server_after_reboot()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_server_after_reboot(self, iface = INTF_RX_DEFAULT):
          ''' DHCP server goes down.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
          log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          else:
                new_cip, new_sip = self.dhcp.only_request(cip, mac)
                if new_cip == None:
                        log.info("Got DHCP server NAK.")
                        assert_not_equal(new_cip, None)
                log.info('Getting DHCP server Down.')
                onos_ctrl = OnosCtrl(self.dhcp_app)
                onos_ctrl.deactivate()
                for i in range(0,4):
                        log.info("Sending DHCP Request.")
                        log.info('')
                        new_cip, new_sip = self.dhcp.only_request(cip, mac)
                        if new_cip == None and new_sip == None:
                                log.info('')
                                log.info("DHCP Request timed out.")
                        elif new_cip and new_sip:
                                log.info("Got Reply from DHCP server.")
                                assert_equal(new_cip,None) #Neagtive Test Case
                log.info('Getting DHCP server Up.')
#               self.activate_apps(self.dhcp_app)
                onos_ctrl = OnosCtrl(self.dhcp_app)
                status, _ = onos_ctrl.activate()
                assert_equal(status, True)
                time.sleep(3)
                for i in range(0,4):
                        log.info("Sending DHCP Request after DHCP server is up.")
                        log.info('')
                        new_cip, new_sip = self.dhcp.only_request(cip, mac)
                        if new_cip == None and new_sip == None:
                                log.info('')
                                log.info("DHCP Request timed out.")
                        elif new_cip and new_sip:
                                log.info("Got Reply from DHCP server.")
                                assert_equal(new_cip,None) #Neagtive Test Case

      def dhcp_client_rebind_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_rebind_time()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_client_rebind_time(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
          log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          elif cip and sip and mac:
                log.info("Triggering DHCP Request.")
                new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, rebind_time = True)
                if new_cip and new_sip and lval:
                        log.info("Client 's Rebind time is :%s",lval)
                        log.info("Generating delay till rebind time.")
                        time.sleep(lval)
                        log.info("Client Sending broadcast DHCP requests for renewing lease or for getting new ip.")
                        self.dhcp.after_T2 = True
                        for i in range(0,4):
                                latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac)
                                if latest_cip and latest_sip:
                                        log.info("Got DHCP Ack. Lease Renewed for ip %s and mac %s from server %s." %
                                                        (latest_cip, mac, latest_sip) )
                                        break
                                elif latest_cip == None:
                                        log.info("Got DHCP NAK. Lease not renewed.")
                        assert_not_equal(latest_cip, None)
                elif new_cip == None or new_sip == None or lval == None:
                        log.info("Got DHCP NAK.Lease not Renewed.")

      def dhcp_starvation_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_starvation()
                  self.test_status = True
                  return self.test_status


      def subscriber_dhcp_starvation(self, iface = INTF_RX_DEFAULT):
          '''DHCP starve'''
          config = {'startip':'182.17.0.20', 'endip':'182.17.0.69',
                    'ip':'182.17.0.2', 'mac': "ca:fe:c3:fe:ca:fe",
                    'subnet': '255.255.255.0', 'broadcast':'182.17.0.255', 'router':'182.17.0.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
          log.info('Verifying 1 ')
          for x in xrange(50):
              mac = RandMAC()._fix()
              self.send_recv(mac = mac)
          log.info('Verifying 2 ')
          cip, sip = self.send_recv(update_seed = True, validate = False)
          assert_equal(cip, None)
          assert_equal(sip, None)

      def dhcp_same_client_multi_discovers_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_same_client_multiple_discover()
                  self.test_status = True
                  return self.test_status


      def subscriber_dhcp_same_client_multiple_discover(self, iface = INTF_RX_DEFAULT):
          ''' DHCP Client sending multiple discover . '''
          config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                    'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                    'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
                  (cip, sip, mac) )
          log.info('Triggering DHCP discover again.')
          new_cip, new_sip, new_mac , lval = self.dhcp.only_discover()
          if cip == new_cip:
                 log.info('Got same ip for 2nd DHCP discover for client IP %s from server %s for mac %s. Triggering DHCP Request. '
                          % (new_cip, new_sip, new_mac) )
          elif cip != new_cip:
                log.info('Ip after 1st discover %s' %cip)
                log.info('Map after 2nd discover %s' %new_cip)
                assert_equal(cip, new_cip)

      def dhcp_same_client_multi_request_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_same_client_multiple_request()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_same_client_multiple_request(self, iface = INTF_RX_DEFAULT):
          ''' DHCP Client sending multiple repeat DHCP requests. '''
          config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                    'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                    'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
          log.info('Sending DHCP discover and DHCP request.')
          cip, sip = self.send_recv()
          mac = self.dhcp.get_mac(cip)[0]
          log.info("Sending DHCP request again.")
          new_cip, new_sip = self.dhcp.only_request(cip, mac)
          if (new_cip,new_sip) == (cip,sip):
                log.info('Got same ip for 2nd DHCP Request for client IP %s from server %s for mac %s.'
                          % (new_cip, new_sip, mac) )
          elif (new_cip,new_sip):
                log.info('No DHCP ACK')
                assert_equal(new_cip, None)
                assert_equal(new_sip, None)
          else:
                print "Something went wrong."


      def dhcp_client_desired_ip_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_desired_address()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_client_desired_address(self, iface = INTF_RX_DEFAULT):
          '''DHCP Client asking for desired IP address.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.31', iface = iface)
          cip, sip, mac , lval = self.dhcp.only_discover(desired = True)
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
          if cip == self.dhcp.seed_ip:
                log.info('Got dhcp client IP %s from server %s for mac %s as desired .' %
                  (cip, sip, mac) )
          elif cip != self.dhcp.seed_ip:
                log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
                log.info('The desired ip was: %s .' % self.dhcp.seed_ip)
                assert_equal(cip, self.dhcp.seed_ip)

      def dhcp_client_request_pkt_with_non_offered_ip_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_server_nak_packet()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_server_nak_packet(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
          log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          else:
                new_cip, new_sip = self.dhcp.only_request('20.20.20.31', mac)
                if new_cip == None:
                        log.info("Got DHCP server NAK.")
                        assert_equal(new_cip, None)  #Negative Test Case

      def dhcp_client_requested_out_pool_ip_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_desired_address_out_of_pool()
                  self.test_status = True
                  return self.test_status


      def subscriber_dhcp_client_desired_address_out_of_pool(self, iface = INTF_RX_DEFAULT):
          '''DHCP Client asking for desired IP address from out of pool.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.35', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover(desired = True)
          log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
          if cip == self.dhcp.seed_ip:
                log.info('Got dhcp client IP %s from server %s for mac %s as desired .' %
                  (cip, sip, mac) )
                assert_equal(cip, self.dhcp.seed_ip) #Negative Test Case

          elif cip != self.dhcp.seed_ip:
                log.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
                log.info('The desired ip was: %s .' % self.dhcp.seed_ip)
                assert_not_equal(cip, self.dhcp.seed_ip)

          elif cip == None:
                log.info('Got DHCP NAK')


      def dhcp_client_specific_lease_scenario(self, subscriber):
            if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_specific_lease_packet()
                  self.test_status = True
                  return self.test_status

      def subscriber_dhcp_specific_lease_packet(self, iface = INTF_RX_DEFAULT):
          ''' Client sends DHCP Discover packet for particular lease time.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          log.info('Sending DHCP discover with lease time of 700')
          cip, sip, mac, lval = self.dhcp.only_discover(lease_time = True)

          log.info("Verifying Client 's IP and mac in DHCP Offer packet.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          elif lval != 700:
                log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s. That is not 700.' %
                         (cip, sip, mac, lval) )
                assert_not_equal(lval, 700)

      def test_subscriber_join_recv_channel(self):
          ###"""Test subscriber join and receive"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify),
                                                    port_list = self.generate_port_list(num_subscribers, num_channels))
          assert_equal(test_status, True)

      def test_subscriber_join_jump_channel(self):
          ###"""Test subscriber join and receive for channel surfing"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.tls_verify, self.dhcp_jump_verify, self.igmp_jump_verify),
                                                    port_list = self.generate_port_list(num_subscribers, num_channels))
          assert_equal(test_status, True)

      def test_subscriber_join_next_channel(self):
          ###"""Test subscriber join next for channels"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.tls_verify, self.dhcp_next_verify, self.igmp_next_verify),
                                                    port_list = self.generate_port_list(num_subscribers, num_channels))
          assert_equal(test_status, True)

      #@deferred(SUBSCRIBER_TIMEOUT)
      def test_subscriber_authentication_with_invalid_certificate_and_channel_surfing(self):
          ### """Test subscriber to auth with invalidCertification and join channel"""
          num_subscribers = 1
          num_channels = 1
          df = defer.Deferred()
          def sub_auth_invalid_cert(df):
              test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                        num_channels = num_channels,
                                                        cbs = (self.tls_invalid_cert, self.dhcp_verify, self.igmp_verify),
                                                        port_list = self.generate_port_list(num_subscribers, num_channels),                                                                                  negative_subscriber_auth = 'all')
              assert_equal(test_status, False)
              df.callback(0)
          reactor.callLater(0, sub_auth_invalid_cert, df)
          return df


      #@deferred(SUBSCRIBER_TIMEOUT)
      def test_subscriber_authentication_with_no_certificate_and_channel_surfing(self):
          ### """Test subscriber to auth with No Certification and join channel"""
          num_subscribers = 1
          num_channels = 1
          df = defer.Deferred()
          def sub_auth_no_cert(df):
              test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                        num_channels = num_channels,
                                                        cbs = (self.tls_no_cert, self.dhcp_verify, self.igmp_verify),
                                                        port_list = self.generate_port_list(num_subscribers, num_channels),
                                                        negative_subscriber_auth = 'all')
              assert_equal(test_status, False)
              df.callback(0)
          reactor.callLater(0, sub_auth_no_cert, df)
          return df

      def test_subscriber_authentication_with_self_signed_certificate_and_channel_surfing(self):
          ### """Test subscriber to auth with Self Signed Certification and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                           num_channels = num_channels,
                                           cbs = (self.tls_self_signed_cert, self.dhcp_verify, self.igmp_verify),
                                           port_list = self.generate_port_list(num_subscribers, num_channels),
                                           negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_discover_and_channel_surfing(self):
          ### """Test subscriber auth success, DHCP re-discover with DHCP server and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                   num_channels = num_channels,
                                                   cbs = (self.tls_verify, self.dhcp_discover_scenario, self.igmp_verify),
                                                   port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_client_reboot_scenario_and_channel_surfing(self):
          ### """Test subscriber auth success, DHCP client got re-booted and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                num_channels = num_channels,
                                                cbs = (self.tls_verify, self.dhcp_client_reboot_scenario, self.igmp_verify),
                                                port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_server_reboot_scenario_and_channel_surfing(self):
          ### """Test subscriber auth , DHCP server re-boot during DHCP process and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                              num_channels = num_channels,
                                              cbs = (self.tls_verify, self.dhcp_server_reboot_scenario, self.igmp_verify),
                                              port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_client_rebind_and_channel_surfing(self):
          ### """Test subscriber auth , DHCP client rebind IP and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                num_channels = num_channels,
                                                cbs = (self.tls_verify, self.dhcp_client_rebind_scenario, self.igmp_verify),
                                                port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)


      def test_subscriber_authentication_with_dhcp_starvation_scenario_and_channel_surfing(self):
          ### """Test subscriber auth , DHCP starvation and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                                num_channels = num_channels,
                                                cbs = (self.tls_verify, self.dhcp_starvation_scenario, self.igmp_verify),
                                                port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_multiple_dhcp_discover_for_same_subscriber_and_channel_surfing(self):
          ### """Test subscriber auth , sending same DHCP client discover multiple times and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                   num_channels = num_channels,
                                   cbs = (self.tls_verify, self.dhcp_same_client_multi_discovers_scenario, self.igmp_verify),
                                   port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_multiple_dhcp_request_for_same_subscriber_and_channel_surfing(self):
          ### """Test subscriber auth , same DHCP client multiple requerts times and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                     num_channels = num_channels,
                                     cbs = (self.tls_verify, self.dhcp_same_client_multi_request_scenario, self.igmp_verify),
                                     port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_client_requested_ip_and_channel_surfing(self):
          ### """Test subscriber auth with DHCP client requesting ip and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                                     num_channels = num_channels,
                                     cbs = (self.tls_verify, self.dhcp_client_desired_ip_scenario, self.igmp_verify),
                                     port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_non_offered_ip_and_channel_surfing(self):
          ### """Test subscriber auth with DHCP client request for non-offered ip and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                        num_channels = num_channels,
                        cbs = (self.tls_verify, self.dhcp_client_request_pkt_with_non_offered_ip_scenario, self.igmp_verify),
                        port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing(self):
          ### """Test subscriber auth with DHCP client requesting out of pool ip and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                               num_channels = num_channels,
                               cbs = (self.tls_verify, self.dhcp_client_requested_out_pool_ip_scenario, self.igmp_verify),
                               port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)

      def test_subscriber_authentication_with_dhcp_specified_lease_time_functionality_and_channel_surfing(self):
          ### """Test subscriber auth with DHCP client specifying lease time and join channel"""
          num_subscribers = 1
          num_channels = 1
          test_status = self.subscriber_join_verify(num_subscribers = num_subscribers,
                               num_channels = num_channels,
                               cbs = (self.tls_verify, self.dhcp_client_specific_lease_scenario, self.igmp_verify),
                               port_list = self.generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'all')
          assert_equal(test_status, True)
