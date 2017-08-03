import os
import sys
import unittest
import time, monotonic
import json
import requests
import threading
from IGMP import *
from random import randint
from threading import Timer
from threadPool import ThreadPool
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from CordTestConfig import setup_module, teardown_module
from CordTestUtils import log_test
from VolthaCtrl import VolthaCtrl, voltha_setup, voltha_teardown
from CordTestUtils import log_test, get_controller
from portmaps import g_subscriber_port_map
from OltConfig import *
from EapTLS import TLSAuthTest
from Channels import Channels, IgmpChannel
from Stats import Stats
from DHCP import DHCPTest
from OnosCtrl import OnosCtrl
from CordLogger import CordLogger
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *
from CordTestServer import cord_test_onos_restart, cord_test_shell, cord_test_radius_restart
from CordContainer import Onos


class Voltha_olt_subscribers(Channels):

      STATS_RX = 0
      STATS_TX = 1
      STATS_JOIN = 2
      STATS_LEAVE = 3

      def __init__(self, tx_port, rx_port, num_channels =1, channel_start = 0, src_list = None):
          self.tx_port = tx_port
          self.rx_port = rx_port
          self.src_list = src_list
          self.num_channels = num_channels
          try:
              self.tx_intf = tx_port
              self.rx_intf = rx_port
          except:
              self.tx_intf = self.INTF_TX_DEFAULT
              self.rx_intf = self.INTF_RX_DEFAULT
#          num = 1
#          channel_start = 0
          mcast_cb = None
          Channels.__init__(self, num_channels, channel_start = channel_start, src_list = src_list,
                              iface = self.rx_intf, iface_mcast = self.tx_intf, mcast_cb = mcast_cb)

          self.loginType  = 'wireless'
          ##start streaming channels
          self.join_map = {}
          ##accumulated join recv stats
          self.join_rx_stats = Stats()
          self.recv_timeout = False


      def channel_join_update(self, chan, join_time):
            self.join_map[chan] = ( Stats(), Stats(), Stats(), Stats() )
            self.channel_update(chan, self.STATS_JOIN, 1, t = join_time)

      def channel_join(self, chan = 0, delay = 2, src_list = None, record_type = None):
            '''Join a channel and create a send/recv stats map'''
            if self.join_map.has_key(chan):
                  del self.join_map[chan]
            self.delay = delay
            chan, join_time = self.join(chan, src_list = src_list, record_type = record_type)
            #chan, join_time = self.join(chan)
            self.channel_join_update(chan, join_time)
            return chan

      def channel_join_next(self, delay = 2, src_list = None, leave_flag = True):
            '''Joins the next channel leaving the last channel'''
            if self.last_chan:
                  if self.join_map.has_key(self.last_chan):
                        del self.join_map[self.last_chan]
            self.delay = delay
            chan, join_time = self.join_next(src_list = src_list, leave_flag = leave_flag)
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

      def channel_leave(self, chan = 0, force = False, src_list = None):
            if self.join_map.has_key(chan):
                  del self.join_map[chan]
            self.leave(chan, force = force, src_list = src_list)

      def channel_update(self, chan, stats_type, packets, t=0):
            if type(chan) == type(0):
                  chan_list = (chan,)
            else:
                  chan_list = chan
            for c in chan_list:
                  if self.join_map.has_key(c):
                        self.join_map[c][stats_type].update(packets = packets, t = t)

      def channel_receive(self, chan, cb = None, count = 1, timeout = 5, src_list = None):
            log_test.info('Subscriber on port %s checking data traffic receiving from group %s, channel %d' %
                     (self.rx_intf, self.gaddr(chan), chan))
            r = self.recv(chan, cb = cb, count = count, timeout = timeout, src_list = src_list)
            if len(r) == 0:
                  log_test.info('Subscriber on port %s timed out' %( self.rx_intf))
                  self.test_status = False
            else:
                  self.test_status = True
                  pass
#                  log_test.info('Subscriber on port %s received %d packets' %(self.rx_intf, len(r)))
            if self.recv_timeout:
                  ##Negative test case is disabled for now
                  log_test.info('Subscriber on port %s not received %d packets' %(self.rx_intf, len(r)))
                  assert_equal(len(r), 0)
                  self.test_status = True
            return self.test_status

      def channel_not_receive(self, chan, cb = None, count = 1, timeout = 5, src_list = None):
            log_test.info('Subscriber on port %s checking data traffic receiving from group %s, channel %d' %
                     (self.rx_intf, self.gaddr(chan), chan))
            r = self.not_recv(chan, cb = cb, count = count, timeout = timeout, src_list = src_list)
            if len(r) == 0:
                  log_test.info('Subscriber on port %s timed out' %( self.rx_intf))
                  self.test_status = True
            else:
                  self.test_status = False
                  pass
#                  log_test.info('Subscriber on port %s received %d packets' %(self.rx_intf, len(r)))
            if self.recv_timeout:
                  ##Negative test case is disabled for now
                  log_test.info('Subscriber on port %s not received %d packets' %(self.rx_intf, len(r)))
                  assert_equal(len(r), 0)
                  self.test_status = True
            return self.test_status


      def recv_channel_cb(self, pkt, src_list = None):

            ##First verify that we have received the packet for the joined instance
            log_test.info('Packet received for group %s, subscriber, port %s and from source ip %s showing full packet %s'%
                     (pkt[IP].dst, self.rx_intf, pkt[IP].src, pkt.show))
            if src_list is not None:
               for i in src_list:
                   if pkt[IP].src == src_list[i]:
                      pass
                   else:
                      log_test.info('Packet received for group %s, subscriber, port %s and from source ip %s which is not expcted on that port'%
                                                    (pkt[IP].dst, self.rx_intf, pkt[IP].src))

                      self.recv_timeout = True

            if self.recv_timeout:
                  return
            chan = self.caddr(pkt[IP].dst)
            assert_equal(chan in self.join_map.keys(), True)
            recv_time = monotonic.monotonic() * 1000000
            join_time = self.join_map[chan][self.STATS_JOIN].start
            delta = recv_time - join_time
            self.join_rx_stats.update(packets=1, t = delta, usecs = True)
            self.channel_update(chan, self.STATS_RX, 1, t = delta)
            log_test.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))

class voltha_subscriber_pool:

      def __init__(self, subscriber, test_cbs):
            self.subscriber = subscriber
            self.test_cbs = test_cbs

      def pool_cb(self):
            for cb in self.test_cbs:
                  if cb:
                        self.test_status = cb(self.subscriber, multiple_sub = True)
                        if self.test_status is not True:
                           ## This is chaining for other sub status has to check again
                           self.test_status = True
                           log_test.info('This service is failed and other services will not run for this subscriber')
                           break
            log_test.info('This Subscriber is tested for multiple service eligibility ')
            self.test_status = True

class voltha_exchange(unittest.TestCase):

    OLT_TYPE = 'tibit_olt'
    OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_HOST = 'localhost'
    VOLTHA_REST_PORT = 8881
    VOLTHA_OLT_TYPE = 'ponsim_olt'
    VOLTHA_OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_IGMP_ITERATIONS = 100
    voltha = None
    voltha_attrs = None
    success = True
    olt_device_id = None
    apps = ('org.opencord.aaa', 'org.onosproject.dhcp', 'org.onosproject.dhcprelay')
    app_dhcp = ('org.onosproject.dhcp')
    olt_apps = () #'org.opencord.cordmcast')
    vtn_app = 'org.opencord.vtn'
    table_app = 'org.ciena.cordigmp'
    test_path = os.path.dirname(os.path.realpath(__file__))
    table_app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-multitable-2.0-SNAPSHOT.oar')
    app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-2.0-SNAPSHOT.oar')
    olt_app_file = os.path.join(test_path, '..', 'apps/olt-app-1.2-SNAPSHOT.oar')
    olt_app_name = 'org.onosproject.olt'
    #onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config.json'))
    onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))
    VOLTHA_AUTO_CONFIGURE = False
    num_joins = 0

    relay_interfaces_last = ()
    interface_to_mac_map = {}
    host_ip_map = {}
    default_config = { 'default-lease-time' : 600, 'max-lease-time' : 7200, }
    default_options = [ ('subnet-mask', '255.255.255.0'),
                     ('broadcast-address', '192.168.1.255'),
                     ('domain-name-servers', '192.168.1.1'),
                     ('domain-name', '"mydomain.cord-tester"'),
                   ]
    ##specify the IP for the dhcp interface matching the subnet and subnet config
    ##this is done for each interface dhcpd server would be listening on
    default_subnet_config = [ ('192.168.1.2',
'''
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.10 192.168.1.100;
}
'''), ]


    VOLTHA_ENABLED  = True
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    INTF_2_RX_DEFAULT = 'veth6'
    TESTCASE_TIMEOUT = 300
    VOLTHA_IGMP_ITERATIONS = 10
#    VOLTHA_CONFIG_FAKE = True
    VOLTHA_CONFIG_FAKE = False
    VOLTHA_UPLINK_VLAN_MAP = { 'of:0000000000000001' : '222' }
    VOLTHA_UPLINK_VLAN_START = 444
    VOLTHA_ONU_UNI_PORT = 'veth0'

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

    @classmethod
    def update_apps_version(cls):
        version = Onos.getVersion()
        major = int(version.split('.')[0])
        minor = int(version.split('.')[1])
        cordigmp_app_version = '2.0-SNAPSHOT'
        olt_app_version = '1.2-SNAPSHOT'
        if major > 1:
            cordigmp_app_version = '3.0-SNAPSHOT'
            olt_app_version = '2.0-SNAPSHOT'
        elif major == 1:
            if minor > 10:
                cordigmp_app_version = '3.0-SNAPSHOT'
                olt_app_version = '2.0-SNAPSHOT'
            elif minor <= 8:
                olt_app_version = '1.1-SNAPSHOT'
            cls.app_file = os.path.join(cls.test_path, '..', 'apps/ciena-cordigmp-{}.oar'.format(cordigmp_app_version))
            cls.table_app_file = os.path.join(cls.test_path, '..', 'apps/ciena-cordigmp-multitable-{}.oar'.format(cordigmp_app_version))
            cls.olt_app_file = os.path.join(cls.test_path, '..', 'apps/olt-app-{}.oar'.format(olt_app_version))

    @classmethod
    def dhcprelay_setUpClass(cls):
        ''' Activate the dhcprelay app'''
        OnosCtrl(cls.app_dhcp).deactivate()
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl('org.onosproject.dhcprelay')
        status, _ = cls.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)
        cls.dhcp_relay_setup()
        ##start dhcpd initially with default config
        cls.dhcpd_start()

    @classmethod
    def dhcprelay_tearDownClass(cls):
        '''Deactivate the dhcp relay app'''
        try:
            os.unlink('{}/dhcpd.conf'.format(cls.dhcp_data_dir))
            os.unlink('{}/dhcpd.leases'.format(cls.dhcp_data_dir))
        except: pass
        cls.onos_ctrl.deactivate()
        cls.dhcpd_stop()
        cls.dhcp_relay_cleanup()

    @classmethod
    def onos_load_config(cls, app, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON config request for app %s returned status %d' %(app, code))
            assert_equal(status, True)
        time.sleep(2)

    @classmethod
    def onos_aaa_load(cls):
        aaa_dict = {'apps' : { 'org.opencord.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                'radiusIp': '172.17.0.2' } } } }
        radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
        aaa_dict['apps']['org.opencord.aaa']['AAA']['radiusIp'] = radius_ip
        cls.onos_load_config('org.opencord.aaa', aaa_dict)

    @classmethod
    def onos_dhcp_table_load(self, config = None):
        dhcp_dict = {'apps' : { 'org.onosproject.dhcp' : { 'dhcp' : copy.copy(self.dhcp_server_config) } } }
        dhcp_config = dhcp_dict['apps']['org.onosproject.dhcp']['dhcp']
        if config:
           for k in config.keys():
               if dhcp_config.has_key(k):
                  dhcp_config[k] = config[k]
        self.onos_load_config('org.onosproject.dhcp', dhcp_dict)

    def dhcp_sndrcv(self, dhcp, update_seed = False, mac = None, validation = None):
        if validation:
           cip, sip = dhcp.discover(mac = mac, update_seed = update_seed)
           assert_not_equal(cip, None)
           assert_not_equal(sip, None)
           log_test.info('Got dhcp client IP %s from server %s for mac %s' %
                   (cip, sip, dhcp.get_mac(cip)[0]))
        if validation == False:
           cip, sip = dhcp.discover(mac = mac, update_seed = update_seed)
           assert_equal(cip, None)
           assert_equal(sip, None)
           log_test.info('Dhcp client did not get IP from server')

        if validation == 'skip':
           cip, sip = dhcp.discover(mac = mac, update_seed = update_seed)

        return cip,sip

    def dhcp_request(self, onu_iface = None, seed_ip = '10.10.10.1', update_seed = False, validation = None, startip = '10.10.10.20', mac = None):
        config = {'startip':startip, 'endip':'10.10.10.200',
                  'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        dhcp = DHCPTest(seed_ip = seed_ip, iface =onu_iface)
        cip, sip = self.dhcp_sndrcv(dhcp, update_seed = update_seed, validation = validation, mac = mac)
        return cip, sip

    @classmethod
    def setUpClass(cls):
        cls.update_apps_version()
        cls.voltha_attrs = dict(host = cls.VOLTHA_HOST,
                                rest_port = cls.VOLTHA_REST_PORT,
                                uplink_vlan_map = cls.VOLTHA_UPLINK_VLAN_MAP,
                                uplink_vlan_start = cls.VOLTHA_UPLINK_VLAN_START)
        cls.voltha = VolthaCtrl(**cls.voltha_attrs)
        cls.install_app_table()
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, cls.port_list = cls.olt.olt_port_map()
        cls.switches = cls.port_map['switches']
        cls.ponsim_ports = cls.port_map['ponsim']
        cls.num_ports = cls.port_map['num_ports']
        if cls.num_ports > 1:
              cls.num_ports -= 1 ##account for the tx port
        cls.activate_apps(cls.apps + cls.olt_apps, deactivate = True)
        cls.onos_aaa_load()

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the olt apps and restart OVS back'''
        apps = cls.olt_apps + ( cls.table_app,)
        for app in apps:
            onos_ctrl = OnosCtrl(app)
            onos_ctrl.deactivate()
        cls.install_app_igmp()
        cord_test_radius_restart()

    @classmethod
    def install_app_igmp(cls):
        ##Uninstall the table app on class exit
        OnosCtrl.uninstall_app(cls.table_app)
        time.sleep(2)
        log_test.info('Installing back the cord igmp app %s for subscriber test on exit' %(cls.app_file))
        OnosCtrl.install_app(cls.app_file)

    def remove_olt(self, switch_map):
        controller = get_controller()
        auth = ('karaf', 'karaf')
        #remove subscriber for every port on all the voltha devices
        for device, device_map in switch_map.iteritems():
            uni_ports = device_map['ports']
            uplink_vlan = device_map['uplink_vlan']
            for port in uni_ports:
                rest_url = 'http://{}:8181/onos/olt/oltapp/{}/{}'.format(controller,
                                                                         device,
                                                                         port)
                resp = requests.delete(rest_url, auth = auth)
                if resp.status_code not in [204, 202, 200]:
                      log_test.error('Error deleting subscriber for device %s on port %s' %(device, port))
                else:
                      log_test.info('Deleted subscriber for device %s on port  %s' %(device, port))
        OnosCtrl.uninstall_app(self.olt_app_file)

    def config_olt(self, switch_map):
        controller = get_controller()
        auth = ('karaf', 'karaf')
        #configure subscriber for every port on all the voltha devices
        for device, device_map in switch_map.iteritems():
            uni_ports = device_map['ports']
            uplink_vlan = device_map['uplink_vlan']
            for port in uni_ports:
                vlan = port
                rest_url = 'http://{}:8181/onos/olt/oltapp/{}/{}/{}'.format(controller,
                                                                            device,
                                                                            port,
                                                                            vlan)
                resp = requests.post(rest_url, auth = auth)
                #assert_equal(resp.ok, True)

    def voltha_uni_port_toggle(self, uni_port = None):
        ## Admin state of port is down and up
        if not uni_port:
           uni_port = self.INTF_RX_DEFAULT
        cmd = 'ifconfig {} down'.format(uni_port)
        os.system(cmd)
        log_test.info('Admin state of uni_port is down')
        time.sleep(30)
        cmd = 'ifconfig {} up'.format(uni_port)
        os.system(cmd)
        log_test.info('Admin state of uni_port is up now')
        time.sleep(30)
        return

    @classmethod
    def install_app_table(cls):
        ##Uninstall the existing app if any
        OnosCtrl.uninstall_app(cls.table_app)
        time.sleep(2)
        log_test.info('Installing the multi table app %s for subscriber test' %(cls.table_app_file))
        OnosCtrl.install_app(cls.table_app_file)
        time.sleep(3)

    @classmethod
    def activate_apps(cls, apps, deactivate = False):
        for app in apps:
            onos_ctrl = OnosCtrl(app)
            if deactivate is True:
               onos_ctrl.deactivate()
               time.sleep(2)
               status, _ = onos_ctrl.activate()
               assert_equal(status, True)
               time.sleep(2)



    @classmethod
    def deactivate_apps(cls, apps):
        cls.success = True
        for app in apps:
            onos_ctrl = OnosCtrl(app)
            status, _ = onos_ctrl.deactivate()
            if status is False:
               cls.success = False
    #        assert_equal(status, True)
            time.sleep(2)

    def random_ip(self,start_ip = '10.10.10.20', end_ip = '10.10.10.65'):
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

    @classmethod
    def dhcp_relay_setup(cls):
        #did = OnosCtrl.get_device_id()
        #cls.relay_device_id = did
        #cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        #cls.port_map, _ = cls.olt.olt_port_map() self.port_map['ports'][port_list[1][1]]
        if cls.port_map:
            ##Per subscriber, we use 1 relay port
            try:
                relay_port = cls.port_map['ports']
            except:
                relay_port = cls.port_map['uplink']
            cls.relay_interface_port = relay_port
            cls.relay_interfaces = (cls.port_map[cls.relay_interface_port],)
        else:
#            cls.relay_interface_port = 100
#            cls.relay_interfaces = (g_subscriber_port_map[cls.relay_interface_port],)
             log_test.info('No ONU ports are available, hence returning nothing')
        cls.relay_interfaces_last = cls.relay_interfaces
        if cls.port_map:
            ##generate a ip/mac client virtual interface config for onos
            interface_list = []
            for port in cls.port_map['ports']:
                port_num = cls.port_map[port]
                if port_num == cls.port_map['uplink']:
                    continue
                ip = cls.get_host_ip(port_num)
                mac = cls.get_mac(port)
                interface_list.append((port_num, ip, mac))

            #configure dhcp server virtual interface on the same subnet as first client interface
            relay_ip = cls.get_host_ip(interface_list[0][0])
            relay_mac = cls.get_mac(cls.port_map[cls.relay_interface_port])
            interface_list.append((cls.relay_interface_port, relay_ip, relay_mac))
            cls.onos_interface_load(interface_list)

    @classmethod
    def onos_interface_load(cls, interface_list):
        interface_dict = { 'ports': {} }
        for port_num, ip, mac in interface_list:
            port_map = interface_dict['ports']
            port = '{}/{}'.format(cls.relay_device_id, port_num)
            port_map[port] = { 'interfaces': [] }
            interface_list = port_map[port]['interfaces']
            interface_map = { 'ips' : [ '{}/{}'.format(ip, 24) ],
                              'mac' : mac,
                              'name': 'vir-{}'.format(port_num)
                            }
            interface_list.append(interface_map)

        cls.onos_load_config(interface_dict)
        cls.configs['interface_config'] = interface_dict

    @classmethod
    def get_host_ip(cls, port):
        if cls.host_ip_map.has_key(port):
            return cls.host_ip_map[port]
        cls.host_ip_map[port] = '192.168.1.{}'.format(port)
        return cls.host_ip_map[port]

    @classmethod
    def host_load(cls, iface):
        '''Have ONOS discover the hosts for dhcp-relay responses'''
        port = g_subscriber_port_map[iface]
        host = '173.17.1.{}'.format(port)
        cmds = ( 'ifconfig {} 0'.format(iface),
                 'ifconfig {0} {1}'.format(iface, host),
                 'arping -I {0} {1} -c 2'.format(iface, host),
                 'ifconfig {} 0'.format(iface), )
        for c in cmds:
            os.system(c)

    @classmethod
    def dhcpd_conf_generate(cls, config = default_config, options = default_options,
                            subnet = default_subnet_config):
        conf = ''
        for k, v in config.items():
            conf += '{} {};\n'.format(k, v)

        opts = ''
        for k, v in options:
            opts += 'option {} {};\n'.format(k, v)

        subnet_config = ''
        for _, v in subnet:
            subnet_config += '{}\n'.format(v)

        return '{}{}{}'.format(conf, opts, subnet_config)

    @classmethod
    def dhcpd_start(cls, intf_list = None,
                    config = default_config, options = default_options,
                    subnet = default_subnet_config):
        '''Start the dhcpd server by generating the conf file'''
        if intf_list is None:
            intf_list = cls.relay_interfaces
        ##stop dhcpd if already running
        cls.dhcpd_stop()
        dhcp_conf = cls.dhcpd_conf_generate(config = config, options = options,
                                            subnet = subnet)
        ##first touch dhcpd.leases if it doesn't exist
        lease_file = '{}/dhcpd.leases'.format(cls.dhcp_data_dir)
        if os.access(lease_file, os.F_OK) is False:
            with open(lease_file, 'w') as fd: pass

        conf_file = '{}/dhcpd.conf'.format(cls.dhcp_data_dir)
        with open(conf_file, 'w') as fd:
            fd.write(dhcp_conf)

        #now configure the dhcpd interfaces for various subnets
        index = 0
        intf_info = []
        for ip,_ in subnet:
            intf = intf_list[index]
            mac = cls.get_mac(intf)
            intf_info.append((ip, mac))
            index += 1
            os.system('ifconfig {} {}'.format(intf, ip))

        intf_str = ','.join(intf_list)
        dhcpd_cmd = '/usr/sbin/dhcpd -4 --no-pid -cf {0} -lf {1} {2}'.format(conf_file, lease_file, intf_str)
        log_test.info('Starting DHCPD server with command: %s' %dhcpd_cmd)
        ret = os.system(dhcpd_cmd)
        assert_equal(ret, 0)
        time.sleep(3)
        cls.relay_interfaces_last = cls.relay_interfaces
        cls.relay_interfaces = intf_list
        cls.onos_dhcp_relay_load(*intf_info[0])

    @classmethod
    def dhcpd_stop(cls):
        os.system('pkill -9 dhcpd')
        for intf in cls.relay_interfaces:
            os.system('ifconfig {} 0'.format(intf))

        cls.relay_interfaces = cls.relay_interfaces_last

    @classmethod
    def get_mac(cls, iface):
        if cls.interface_to_mac_map.has_key(iface):
            return cls.interface_to_mac_map[iface]
        mac = get_mac(iface, pad = 0)
        cls.interface_to_mac_map[iface] = mac
        return mac

    def send_recv(self, mac=None, update_seed = False, validate = True):
        cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
        if validate:
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
        log_test.info('Got dhcp client IP %s from server %s for mac %s' %
                (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip

    @classmethod
    def dhcpd_conf_generate(cls, config = default_config, options = default_options,
                            subnet = default_subnet_config):
        conf = ''
        for k, v in config.items():
            conf += '{} {};\n'.format(k, v)

        opts = ''
        for k, v in options:
            opts += 'option {} {};\n'.format(k, v)

        subnet_config = ''
        for _, v in subnet:
            subnet_config += '{}\n'.format(v)

        return '{}{}{}'.format(conf, opts, subnet_config)

    @classmethod
    def onos_dhcp_relay_load(cls, server_ip, server_mac):
        relay_device_map = '{}/{}'.format(cls.relay_device_id, cls.relay_interface_port)
        dhcp_dict = {'apps':{'org.onosproject.dhcp-relay':{'dhcprelay':
                                                          {'dhcpserverConnectPoint':relay_device_map,
                                                           'serverip':server_ip,
                                                           'servermac':server_mac
                                                           }
                                                           }
                             }
                     }
        cls.onos_load_config(dhcp_dict)
        cls.configs['relay_config'] = dhcp_dict

    @classmethod
    def dhcp_relay_cleanup(cls):
        ##reset the ONOS port configuration back to default
        for config in cls.configs.items():
            OnosCtrl.delete(config)
        # if cls.onos_restartable is True:
        #     log_test.info('Cleaning up dhcp relay config by restarting ONOS with default network cfg')
        #     return cord_test_onos_restart(config = {})


    def tls_flow_check(self, olt_ports, cert_info = None, multiple_sub = False):
        if multiple_sub is True:
           olt_nni_port = olt_ports.tx_port
           olt_uni_port = olt_ports.rx_port
        else:
           olt_uni_port = olt_ports

        def tls_fail_cb():
             log_test.info('TLS verification failed')
        if cert_info is None:
           tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = olt_uni_port)
           log_test.info('Running subscriber %s tls auth test with valid TLS certificate' %olt_uni_port)
           tls.runTest()
           if tls.failTest is True:
              self.success = False
           assert_equal(tls.failTest, False)
        if cert_info == "no_cert":
           tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = olt_uni_port, client_cert = '')
           log_test.info('Running subscriber %s tls auth test with no TLS certificate' %olt_uni_port)
           tls.runTest()
           if tls.failTest is False:
              self.success = False
           assert_equal(tls.failTest, True)
        if cert_info == "invalid_cert":
           tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = olt_uni_port, client_cert = self.CLIENT_CERT_INVALID)
           log_test.info('Running subscriber %s tls auth test with invalid TLS certificate' %olt_uni_port)
           tls.runTest()
           if tls.failTest is False:
              self.success = False
           assert_equal(tls.failTest, True)
        if cert_info == "same_cert":
           tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = olt_uni_port)
           log_test.info('Running subscriber %s tls auth test with same valid TLS certificate' %olt_uni_port)
           tls.runTest()
           if tls.failTest is True:
              self.success = False
           assert_equal(tls.failTest, False)
        if cert_info == "app_deactivate" or cert_info == "restart_radius" or cert_info == "disable_olt_device" or \
           cert_info == "uni_port_admin_down" or cert_info == "restart_olt_device" or cert_info == "restart_onu_device":
           tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = olt_uni_port, client_cert = self.CLIENT_CERT_INVALID)
           log_test.info('Running subscriber %s tls auth test with %s' %(olt_uni_port,cert_info))
           tls.runTest()
           if tls.failTest is False:
              self.success = False
           assert_equal(tls.failTest, True)
        self.test_status = True
        return self.test_status

    def dhcp_flow_check(self, olt_ports, negative_test = None, multiple_sub = False):
        if multiple_sub is True:
           olt_nni_port = olt_ports.tx_port
           onu_iface = olt_ports.rx_port
           dhcp_server_startip = self.random_ip()
           random_mac = '00:00:00:0a:0a:' + hex(random.randrange(50,254)).split('x')[1]
        else:
          onu_iface = olt_ports
          dhcp_server_startip = '10.10.10.20'
          random_mac = None
        self.success = True

        if negative_test is None:
           cip, sip = self.dhcp_request(onu_iface, update_seed = True, validation = 'skip', startip = dhcp_server_startip, mac = random_mac)
           if cip == None or sip == None:
              self.success = False
              self.test_status = False
              assert_not_equal(cip,None)
              assert_not_equal(sip,None)
           else:
              log_test.info('Subscriber %s client ip %s from server %s' %(onu_iface, cip, sip))
              self.test_status = True

        if negative_test == "interrupting_dhcp_flows":
           cip, sip = self.dhcp_request(onu_iface, update_seed = True, validation = False)
           if cip is not None:
              self.success =  False
           assert_equal(cip,None)
           log_test.info('Subscriber %s not got client ip %s from server' %(onu_iface, cip))
           self.test_status = True

        if negative_test == "invalid_src_mac_broadcast":
           config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                     'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover(mac='ff:ff:ff:ff:ff:ff')

           if cip is not None:
              self.success =  False
           log_test.info('ONOS dhcp server rejected client discover with invalid source mac as expected self.success = %s '%self.success)
           assert_equal(cip,None)
           log_test.info('ONOS dhcp server rejected client discover with invalid source mac as expected')
           self.test_status = True

        if negative_test == "invalid_src_mac_multicast":
           config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                     'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover(mac='01:80:c2:91:02:e4')
           if cip is not None:
              self.success =  False
           assert_equal(cip,None)
           log_test.info('ONOS dhcp server rejected client discover with invalid source mac as expected')
           self.test_status = True

        if negative_test == "invalid_src_mac_junk":
           config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                     'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover(mac='00:00:00:00:00:00')
           if cip is not None:
              self.success =  False
           assert_equal(cip,None)
           log_test.info('ONOS dhcp server rejected client discover with invalid source mac as expected')
           self.test_status = True

        if negative_test == "request_release":
           config = {'startip':'10.10.100.20', 'endip':'10.10.100.230',
                     'ip':'10.10.100.2', 'mac': "ca:fe:ca:fe:8a:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.100.255', 'router':'10.10.100.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = onu_iface)
           cip, sip = self.dhcp_sndrcv(self.dhcp)
           log_test.info('Releasing ip %s to server %s' %(cip, sip))
           if not self.dhcp.release(cip):
              self.success =  False
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           cip2, sip2 = self.dhcp_sndrcv(self.dhcp, update_seed = True)
           log_test.info('Verifying released IP was given back on rediscover')
           if not cip == cip2:
              self.success =  False
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
           self.test_status = True

        if negative_test == "starvation_positive":
           config = {'startip':'193.170.1.20', 'endip':'193.170.1.69',
                     'ip':'193.170.1.2', 'mac': "ca:fe:c2:fe:cc:fe",
                     'subnet': '255.255.255.0', 'broadcast':'192.168.1.255', 'router': '192.168.1.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '192.169.1.1', iface = onu_iface)
           ip_map = {}
           for i in range(10):
               cip, sip = self.dhcp_sndrcv(self.dhcp, update_seed = True)
               if ip_map.has_key(cip):
                  self.success =  False
                  log_test.info('IP %s given out multiple times' %cip)
                  assert_equal(False, ip_map.has_key(cip))
               ip_map[cip] = sip
           self.test_status = True

        if negative_test == "starvation_negative":
           config = {'startip':'182.17.0.20', 'endip':'182.17.0.69',
                     'ip':'182.17.0.2', 'mac': "ca:fe:c3:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'182.17.0.255', 'router':'182.17.0.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = onu_iface)
           log_test.info('Verifying passitive case')
           for x in xrange(50):
               mac = RandMAC()._fix()
               self.dhcp_sndrcv(self.dhcp,mac = mac)
           log_test.info('Verifying negative case')
           cip, sip = self.dhcp_sndrcv(self.dhcp,update_seed = True)
           if cip or sip is not None:
              self.success = False
           assert_equal(cip, None)
           assert_equal(sip, None)
           self.test_status = True
           self.success =  True

        if negative_test == "multiple_discover":
           config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                     'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover()
           log_test.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
                       (cip, sip, mac) )
           if cip is None:
              self.success = False
           assert_not_equal(cip, None)
           log_test.info('Triggering DHCP discover again.')
           new_cip, new_sip, new_mac, _ = self.dhcp.only_discover()
           if not new_cip == cip:
              self.success = False
           assert_equal(new_cip, cip)
           log_test.info('client got same IP as expected when sent 2nd discovery')
           self.test_status = True
 #          self.success =  True
        if negative_test == "multiple_requests":
           config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                     'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = onu_iface)
           log_test.info('Sending DHCP discover and DHCP request.')
           cip, sip = self.dhcp_sndrcv(self.dhcp,update_seed = True)
           mac = self.dhcp.get_mac(cip)[0]
           log_test.info("Sending DHCP request again.")
           new_cip, new_sip = self.dhcp.only_request(cip, mac)
           assert_equal(new_cip,cip)
           log_test.info('server offered same IP to clain for multiple requests, as expected')
           self.test_status = True
#           self.success =  True
        if negative_test == "desired_ip_address":
           config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                     'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '20.20.20.50', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
           if cip or sip is None:
              self.success = False
           assert_not_equal(cip, None)
           log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                      (cip, sip, mac))
           if not self.dhcp.seed_ip == cip:
              self.success = False
           assert_equal(cip,self.dhcp.seed_ip)
           log_test.info('ONOS dhcp server offered client requested IP %s as expected'%self.dhcp.seed_ip)
           self.test_status = True
  #         self.success =  True
        if negative_test == "desired_out_of_pool_ip_address":
           config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                     'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '20.20.20.75', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
           if cip or sip is None:
              self.success = False
           assert_not_equal(cip, None)
           log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                      (cip, sip, mac) )
           if self.dhcp.seed_ip == cip:
              self.success = False
           assert_not_equal(cip,self.dhcp.seed_ip)
           log_test.info('server offered IP from its pool of IPs when requested out of pool IP, as expected')
           self.test_status = True
   #        self.success =  True
        if negative_test == "dhcp_renew":
           config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                     'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover()
           log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                                            (cip, sip, mac) )
           if cip or sip is None:
              self.success = False
           assert_not_equal(cip, None)
           new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
           log_test.info('waiting renew  time %d seconds to send next request packet'%lval)
           time.sleep(lval)
           latest_cip, latest_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
           if not latest_cip == cip:
              self.success = False
           assert_equal(latest_cip,cip)
           log_test.info('client got same IP after renew time, as expected')
           self.test_status = True
    #       self.success =  True
        if negative_test == "dhcp_rebind":
           config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                     'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                     'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
           self.onos_dhcp_table_load(config)
           self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = onu_iface)
           cip, sip, mac, _ = self.dhcp.only_discover()
           log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                                       (cip, sip, mac) )
           if cip or sip is None:
              self.success = False
           assert_not_equal(cip, None)
           new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, rebind_time = True)
           log_test.info('waiting rebind time %d seconds to send next request packet'%lval)
           time.sleep(lval)
           latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac)
           if not latest_cip == cip:
              self.success = False
           assert_equal(latest_cip,cip)
           log_test.info('client got same IP after rebind time, as expected')
           self.test_status = True
     #      self.success =  True
        return self.test_status

    def recv_channel_cb(self, pkt):
        ##First verify that we have received the packet for the joined instance
        chan = self.subscriber.caddr(pkt[IP].dst)
        assert_equal(chan in self.subscriber.join_map.keys(), True)
        recv_time = monotonic.monotonic() * 1000000
        join_time = self.subscriber.join_map[chan][self.subscriber.STATS_JOIN].start
        delta = recv_time - join_time
        self.subscriber.join_rx_stats.update(packets=1, t = delta, usecs = True)
        self.subscriber.channel_update(chan, self.subscriber.STATS_RX, 1, t = delta)
        log_test.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))
        self.test_status = True

    def traffic_verify(self, subscriber):
   # if subscriber.has_service('TRAFFIC'):
	url = 'http://www.google.com'
	resp = requests.get(url)
	self.test_status = resp.ok
	if resp.ok == False:
	      log_test.info('Subscriber %s failed get from url %s with status code %d'
			 %(subscriber.name, url, resp.status_code))
	else:
	      log_test.info('GET request from %s succeeded for subscriber %s'
			 %(url, subscriber.name))
	return self.test_status

    def igmp_flow_check(self, subscriber, multiple_sub = False):
	chan = 0
        for i in range(self.VOLTHA_IGMP_ITERATIONS + subscriber.num_channels):
            if subscriber.num_channels == 1:
               if i != 0:
                  subscriber.channel_leave(chan, src_list = subscriber.src_list)
               chan = subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
            else:
               chan = subscriber.channel_join_next(delay = 2, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
	         time.sleep(5)
            log_test.info('All subscribers have joined the channel')
    #        for i in range(1):
    	    time.sleep(0.5)
	    self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
	    #log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
	    #subscriber.channel_leave(chan, src_list = subscriber.src_list)
	    time.sleep(5)
#	    log_test.info('Interface %s Join RX stats for subscriber, %s' %(subscriber.iface,subscriber.join_rx_stats))
            if subscriber.num_channels == 1:
               pass
            elif chan != 0:
            #Should not receive packets for this channel
               self.recv_timeout = True
               subscriber.recv_timeout = True
               subscriber.channel_receive(chan-1, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
               subscriber.recv_timeout = False
               self.recv_timeout = False
            log_test.info('Joining channel %d for subscriber port %s' %(chan, subscriber.rx_port))
#	    subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
#            chan = subscriber.num_channels - i
#                  self.test_status = True
	return self.test_status

    def igmp_join_next_channel_flow_check(self, subscriber, multiple_sub = False):
        chan = 0
        for i in range(self.VOLTHA_IGMP_ITERATIONS + subscriber.num_channels):
#            if subscriber.num_channels == 1:
#               chan = subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
#            else:
            chan = subscriber.channel_join_next(delay = 2, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
                 time.sleep(5)
            log_test.info('All subscribers have joined the channel')
    #        for i in range(1):
            time.sleep(0.5)
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
            #log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
            #subscriber.channel_leave(chan, src_list = subscriber.src_list)
            time.sleep(5)
#           log_test.info('Interface %s Join RX stats for subscriber, %s' %(subscriber.iface,subscriber.join_rx_stats))
#            if subscriber.num_channels == 1:
#               pass
#            elif chan != 0:
#               pass
            #Should not receive packets for this channel
#               log_test.info
#               self.recv_timeout = True
#               subscriber.recv_timeout = True
#               subscriber.channel_receive(chan-1, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
#               subscriber.recv_timeout = False
#               self.recv_timeout = False
#           log_test.info('Joining channel %d for subscriber port %s' %(chan, subscriber.rx_port))
#           subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
            chan = subscriber.num_channels - i
#                  self.test_status = True
        return self.test_status


    def igmp_leave_flow_check(self, subscriber, multiple_sub = False):
        chan = 0
        for i in range(self.VOLTHA_IGMP_ITERATIONS):
            subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
                 time.sleep(5)
            log_test.info('All subscribers have joined the channel')
#            for i in range(1):
            time.sleep(0.5)
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
            log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
            subscriber.channel_leave(chan, src_list = subscriber.src_list)
            time.sleep(10)
#           log_test.info('Interface %s Join RX stats for subscriber, %s' %(subscriber.iface,subscriber.join_rx_stats))
        #Should not receive packets for this subscriber
            self.recv_timeout = True
            subscriber.recv_timeout = True
            subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list)
            subscriber.recv_timeout = False
            self.recv_timeout = False
#           log_test.info('Joining channel %d for subscriber port %s' %(chan, subscriber.rx_port))
#           subscriber.channel_join(chan, delay = 2, src_list = subscriber.src_list)
#                  self.test_status = True
        return self.test_status



    def igmp_flow_check_join_change_to_exclude(self, subscriber, multiple_sub = False):
	chan = 2
	subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
	self.num_joins += 1
	while self.num_joins < self.num_subscribers:
	      time.sleep(5)
        log_test.info('All subscribers have joined the channel')
	self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list)
	time.sleep(5)
	chan = 1
	log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
	subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list, record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
	time.sleep(5)
	self.recv_timeout = True
	subscriber.recv_timeout = True
	self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list[1])
	if self.test_status is True:
	   self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list[0])
	   if self.test_status is True:
	      log_test.info('Subscriber should not receive data from channel %s on specific source %s, test is failed' %(chan, subscriber.rx_port))
	      self.test_status = False
        subscriber.recv_timeout = False
	self.recv_timeout = False
	chan = 0
        #for i in range(self.VOLTHA_IGMP_ITERATIONS):
        for i in range(3):
	    subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
	          time.sleep(5)
            log_test.info('All subscribers have joined the channel')
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[1])
            time.sleep(5)
            log_test.info('Leaving channel %d for subscriber on port %s from specific source address %s and waited till GMI timer expires' %(chan, subscriber.rx_port, subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list[0], record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
            #### Adding delay till igmp timer expire data traffic is received from source specific of  subscriber.src_list[0]
            time.sleep(60)
            self.recv_timeout = False
            subscriber.recv_timeout = False
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[1])
            if self.test_status is True:
               self.test_status = subscriber.channel_not_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[0])
            if self.test_status is False:
               subscriber.channel_leave(chan, src_list = subscriber.src_list)
               continue
            subscriber.recv_timeout = False
            self.recv_timeout = False
            subscriber.channel_leave(chan, src_list = subscriber.src_list)
#                self.test_status = True
	return self.test_status

    def igmp_flow_check_join_change_to_exclude_again_include_back(self, subscriber, multiple_sub = False):
        chan = 0
        #for i in range(self.VOLTHA_IGMP_ITERATIONS):
        for i in range(3):
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
                  time.sleep(5)
            log_test.info('All subscribers have joined the channel')
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[1])
            time.sleep(5)
            log_test.info('Leaving channel %d for subscriber on port %s from specific source address %s and waited till GMI timer expires' %(chan, subscriber.rx_port, subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list[0], record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
            #### Adding delay till igmp timer expire data traffic is received from source specific of  subscriber.src_list[0]
            time.sleep(60)
            self.recv_timeout = False
            subscriber.recv_timeout = False
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[1])
            if self.test_status is True:
               self.test_status = subscriber.channel_not_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[0])
            if self.test_status is False:
               subscriber.channel_leave(chan, src_list = subscriber.src_list)
               continue
            subscriber.recv_timeout = False
            self.recv_timeout = False
            log_test.info('Again include the channel %s on port %s with souce list ip %s' %(chan, subscriber.rx_port,subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list, record_type = IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE)
            time.sleep(5)
#            self.recv_timeout = True
#            subscriber.recv_timeout = True
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[0])
            subscriber.recv_timeout = False
            self.recv_timeout = False


            subscriber.channel_leave(chan, src_list = subscriber.src_list)
#                self.test_status = True
        return self.test_status


    def igmp_flow_check_join_change_to_block(self, subscriber, multiple_sub = False):
        chan = 0
        #for i in range(self.VOLTHA_IGMP_ITERATIONS):
        for i in range(3):
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
                  time.sleep(5)
            log_test.info('All subscribers have joined the channel')
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[1])
            time.sleep(5)
            log_test.info('Leaving channel %d for subscriber on port %s from specific source address %s and waited till GMI timer expires' %(chan, subscriber.rx_port, subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list[0], record_type = IGMP_V3_GR_TYPE_BLOCK_OLD)
            #### Adding delay till igmp timer expire data traffic is received from source specific of  subscriber.src_list[0]
            time.sleep(60)
            self.recv_timeout = False
            subscriber.recv_timeout = False
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[1])
            if self.test_status is True:
               self.test_status = subscriber.channel_not_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[0])
            if self.test_status is False:
               subscriber.channel_leave(chan, src_list = subscriber.src_list)
               continue
            subscriber.recv_timeout = False
            self.recv_timeout = False
            subscriber.channel_leave(chan, src_list = subscriber.src_list)
#                self.test_status = True
        return self.test_status


    def igmp_flow_check_join_change_to_block_again_allow_back(self, subscriber, multiple_sub = False):
        chan = 0
        #for i in range(self.VOLTHA_IGMP_ITERATIONS):
        for i in range(3):
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
            self.num_joins += 1
            while self.num_joins < self.num_subscribers:
                  time.sleep(5)
            log_test.info('All subscribers have joined the channel')
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[1])
            time.sleep(5)
            log_test.info('Leaving channel %d for subscriber on port %s from specific source address %s and waited till GMI timer expires' %(chan, subscriber.rx_port, subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list[0], record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
            #### Adding delay till igmp timer expire data traffic is received from source specific of  subscriber.src_list[0]
            time.sleep(60)
            self.recv_timeout = False
            subscriber.recv_timeout = False
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[1])
            if self.test_status is True:
               self.test_status = subscriber.channel_not_receive(chan, cb = subscriber.recv_channel_cb, count = 1, src_list = subscriber.src_list[0])
            if self.test_status is False:
               subscriber.channel_leave(chan, src_list = subscriber.src_list)
               continue
            subscriber.recv_timeout = False
            self.recv_timeout = False
            log_test.info('Again include the channel %s on port %s with souce list ip %s' %(chan, subscriber.rx_port,subscriber.src_list[0]))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list, record_type = IGMP_V3_GR_TYPE_ALLOW_NEW)
            time.sleep(5)
#            self.recv_timeout = True
#            subscriber.recv_timeout = True
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 5, src_list = subscriber.src_list[0])
            subscriber.recv_timeout = False
            self.recv_timeout = False


            subscriber.channel_leave(chan, src_list = subscriber.src_list)
#                self.test_status = True
        return self.test_status

    def igmp_flow_check_group_include_source_empty_list(self, subscriber, multiple_sub = False):
        chan = 0
        subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
        self.num_joins += 1
        while self.num_joins < self.num_subscribers:
              time.sleep(5)
        log_test.info('All subscribers have joined the channel')
        self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
	if self.test_status is True:
           log_test.info('Subscriber should not receive data from channel %s on any specific source %s, test is failed' %(chan, subscriber.rx_port))
           self.test_status = False
        else:
           log_test.info('Subscriber not receive data from channel %s on any specific source %s' %(chan, subscriber.rx_port))
           self.test_status = True
        log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
        subscriber.channel_leave(chan, src_list = subscriber.src_list)
        time.sleep(5)
        subscriber.recv_timeout = False
        self.recv_timeout = False
        return self.test_status

    def igmp_flow_check_group_exclude_source_empty_list(self, subscriber, multiple_sub = False):
        chan = 0
        subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
        self.num_joins += 1
        while self.num_joins < self.num_subscribers:
              time.sleep(5)
        log_test.info('All subscribers have joined the channel')
        self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
        if self.test_status is True:
           log_test.info('Subscriber should not receive data from channel %s on any specific source %s, test is failed' %(chan, subscriber.rx_port))
           self.test_status = False
        else:
           log_test.info('Subscriber not receive data from channel %s on any specific source %s' %(chan, subscriber.rx_port))
           self.test_status = True

        subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list, record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
        log_test.info('Send join to multicast group with exclude empty source list and waited till GMI timer expires')
        time.sleep(60)

        self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
        log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
        subscriber.channel_leave(chan, src_list = subscriber.src_list)
        time.sleep(5)
        subscriber.recv_timeout = False
        self.recv_timeout = False
        return self.test_status

    def igmp_flow_check_group_exclude_source_empty_list_1(self, subscriber, multiple_sub = False):
        chan = 0
        subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list,record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE)
        self.num_joins += 1
        while self.num_joins < self.num_subscribers:
              time.sleep(5)
        log_test.info('All subscribers have joined the channel')
        for i in range(10):
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list)
            log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
            subscriber.channel_leave(chan, src_list = subscriber.src_list)
            time.sleep(5)
            log_test.info('Interface %s Join RX stats for subscriber, %s' %(subscriber.iface,subscriber.join_rx_stats))
        #Should not receive packets for this subscriber
            self.recv_timeout = True
            subscriber.recv_timeout = True
            subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list)
            subscriber.recv_timeout = False
            self.recv_timeout = False
            log_test.info('Joining channel %d for subscriber port %s' %(chan, subscriber.rx_port))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
#                  self.test_status = True
        return self.test_status

    def igmp_flow_check_during_olt_onu_operational_issues(self, subscriber, multiple_sub = False):
        chan = 0
        subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
        self.num_joins += 1
        while self.num_joins < self.num_subscribers:
              time.sleep(5)
        log_test.info('All subscribers have joined the channel')
        for i in range(2):
            self.test_status = subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list)
            log_test.info('Leaving channel %d for subscriber on port %s' %(chan, subscriber.rx_port))
            subscriber.channel_leave(chan, src_list = subscriber.src_list)
            time.sleep(5)
            log_test.info('Interface %s Join RX stats for subscriber, %s' %(subscriber.iface,subscriber.join_rx_stats))
        #Should not receive packets for this subscriber
            self.recv_timeout = True
            subscriber.recv_timeout = True
            subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10, src_list = subscriber.src_list)
            subscriber.recv_timeout = False
            self.recv_timeout = False
            log_test.info('Joining channel %d for subscriber port %s' %(chan, subscriber.rx_port))
            subscriber.channel_join(chan, delay = 0, src_list = subscriber.src_list)
#                  self.test_status = True
        return self.test_status

    def voltha_igmp_jump_verify(self, subscriber):
	    if subscriber.has_service('IGMP'):
		  for i in xrange(subscriber.num):
			log_test.info('Subscriber %s jumping channel' %subscriber.name)
			chan = subscriber.channel_jump(delay=0)
			subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
			log_test.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
			time.sleep(3)
		  log_test.info('Interface %s Jump RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
		  self.test_status = True
		  return self.test_status

    def voltha_igmp_next_verify(self, subscriber):
	  for c in xrange(self.VOLTHA_IGMP_ITERATIONS):
		for i in xrange(subscriber.num):
		      if i:
			    chan = subscriber.channel_join_next(delay=0, leave_flag = self.leave_flag)
			    time.sleep(0.2)
		      else:
			    chan = subscriber.channel_join(i, delay=0)
			    time.sleep(0.2)
			    if subscriber.num == 1:
				  subscriber.channel_leave(chan)
		      log_test.info('Joined next channel %d for subscriber %s' %(chan, subscriber.name))
		      #subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count=1)
		      #log_test.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
	  self.test_status = True
	  return self.test_status

    def voltha_subscribers(self, services, cbs = None, num_subscribers = 1, num_channels = 1, src_list = None):
          """Test subscriber join next for channel surfing"""
          voltha = VolthaCtrl(self.VOLTHA_HOST,
                              rest_port = self.VOLTHA_REST_PORT,
                              uplink_vlan_map = self.VOLTHA_UPLINK_VLAN_MAP)
          if self.VOLTHA_OLT_TYPE.startswith('ponsim'):
             ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
             log_test.info('Enabling ponsim olt')
             device_id, status = voltha.enable_device(self.VOLTHA_OLT_TYPE, address = ponsim_address)
             if device_id != '':
                self.olt_device_id = device_id
          else:
             log_test.info('This setup test cases is developed on ponsim olt only, hence stop execution')
             assert_equal(False, True)

          assert_not_equal(device_id, None)
          if status == False:
                voltha.disable_device(device_id, delete = True)
          assert_equal(status, True)
          time.sleep(10)
          switch_map = None
          olt_configured = False
          try:
                switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
                if not switch_map:
                      log_test.info('No voltha devices found')
                      return
                log_test.info('Installing OLT app')
                OnosCtrl.install_app(self.olt_app_file)
                time.sleep(5)
                log_test.info('Adding subscribers through OLT app')
                self.config_olt(switch_map)
                olt_configured = True
                time.sleep(5)
                self.num_subscribers = num_subscribers
                self.num_channels = num_channels
                test_status = self.subscriber_flows_check(num_subscribers = self.num_subscribers,
                                                          num_channels = self.num_channels,
                                                          cbs = cbs,
                                                          port_list = self.generate_port_list(self.num_subscribers,
                                                                                              self.num_channels),
                                                          src_list = src_list, services = services)
                if test_status is False:
                   self.success = False
                assert_equal(test_status, True)
          finally:
                if switch_map is not None:
                      if olt_configured is True:
                            self.remove_olt(switch_map)
                      voltha.disable_device(device_id, delete = True)
                      time.sleep(10)
                      log_test.info('Uninstalling OLT app')
                      OnosCtrl.uninstall_app(self.olt_app_name)

    def subscriber_flows_check( self, num_subscribers = 1, num_channels = 1,
                                  channel_start = 0, cbs = None, port_list = [], src_list = None,
                                  services = None, negative_subscriber_auth = None):
          self.test_status = False
          self.ovs_cleanup()
          subscribers_count = num_subscribers
          sub_loop_count =  num_subscribers
          if not port_list:
             port_list = self.generate_port_list(num_subscribers, num_channels)
          subscriber_tx_rx_ports = []
          for i in range(num_subscribers):
              subscriber_tx_rx_ports.append(Voltha_olt_subscribers(tx_port = self.port_map[port_list[i][0]],
                                                                   rx_port = self.port_map[port_list[i][1]],
                                                                   num_channels = num_channels,src_list = src_list,))
          self.onos_aaa_load()
          #load the ssm list for all subscriber channels
          igmpChannel = IgmpChannel(src_list = src_list)
          ssm_groups = map(lambda sub: sub.channels, subscriber_tx_rx_ports)
          ssm_list = reduce(lambda ssm1, ssm2: ssm1+ssm2, ssm_groups)
          if src_list is None:
             igmpChannel = IgmpChannel()
             igmpChannel.igmp_load_ssm_config(ssm_list)
          else:
             igmpChannel = IgmpChannel(src_list = src_list)
             igmpChannel.igmp_load_ssm_config(ssm_list, src_list= src_list)

          self.thread_pool = ThreadPool(min(100, subscribers_count), queue_size=1, wait_timeout=1)

          chan_leave = False #for single channel, multiple subscribers
          if cbs is None:
                cbs = (self.tls_flow_check, self.dhcp_flow_check, self.igmp_flow_check)
                chan_leave = True
          for subscriber in subscriber_tx_rx_ports:
                if 'IGMP' in services:
#                   if src_list:
#                      for i in range(len(src_list)):
#                          subscriber.start(src_ip = src_list[i])
#                   else:
#                      subscriber.start()
                    subscriber.start()
                sub_loop_count = sub_loop_count - 1
                pool_object = voltha_subscriber_pool(subscriber, cbs)
                self.thread_pool.addTask(pool_object.pool_cb)
          self.thread_pool.cleanUpThreads()
          for subscriber in subscriber_tx_rx_ports:
                if services and 'IGMP' in services:
#                  if src_list:
#                     for i in range(len(src_list)):
#                         subscriber.stop(src_ip = src_list[i])
#                  else:
#                     subscriber.stop()
                   subscriber.stop()
                if chan_leave is True:
                      subscriber.channel_leave(0)
          subscribers_count = 0
          return self.test_status


    def generate_port_list(self, subscribers, channels):
        return self.port_list[:subscribers]

    @classmethod
    def ovs_cleanup(cls):
            ##For every test case, delete all the OVS groups
            cmd = 'ovs-ofctl del-groups br-int -OOpenFlow11 >/dev/null 2>&1'
            try:
                  cord_test_shell(cmd)
                  ##Since olt config is used for this test, we just fire a careless local cmd as well
                  os.system(cmd)
            finally:
                  return

    def test_olt_enable_disable(self):
        log_test.info('Enabling OLT type %s, MAC %s' %(self.OLT_TYPE, self.OLT_MAC))
        device_id, status = self.voltha.enable_device(self.OLT_TYPE, self.OLT_MAC)
        assert_not_equal(device_id, None)
        try:
            assert_equal(status, True)
            time.sleep(10)
        finally:
            self.voltha.disable_device(device_id, delete = True)

    def test_ponsim_enable_disable(self):
        log_test.info('Enabling ponsim_olt')
        ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
        device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
        assert_not_equal(device_id, None)
        try:
            assert_equal(status, True)
            time.sleep(10)
        finally:
            self.voltha.disable_device(device_id, delete = True)

    def test_subscriber_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  auth request packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber is authenticated successfully.
        """
        ret = voltha_setup(
              host = self.VOLTHA_HOST,
              rest_port = self.VOLTHA_REST_PORT,
              olt_type = 'ponsim_olt',
              uplink_vlan_map = self.VOLTHA_UPLINK_VLAN_MAP,
              uplink_vlan_start = self.VOLTHA_UPLINK_VLAN_START,
              config_fake = self.VOLTHA_CONFIG_FAKE,
              olt_app = self.olt_app_file)
        assert_not_equal(ret, None)
        voltha, device_id, switch_map = ret[0], ret[1], ret[2]
        try:
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT)
            assert_equal(auth_status, True)
        finally:
            if switch_map is not None:
                if olt_configured is True:
                    self.remove_olt(switch_map)
                voltha_teardown(voltha, device_id, switch_map, olt_app = self.olt_app_file)

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_failure(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls without cert auth packet is being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_with_no_cert_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "no_cert")
            try:
                assert_equal(auth_status, True)
                assert_equal(status, True)
                time.sleep(10)
            finally:
                self.remove_olt(switch_map)
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)

        reactor.callLater(0, tls_flow_check_with_no_cert_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_using_invalid_cert(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets and exchange invalid cert from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls with invalid cert auth packet is being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_with_invalid_cert_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "invalid_cert")
            try:
                assert_equal(auth_status, True)
                assert_equal(status, True)
                time.sleep(10)
            finally:
                self.remove_olt(switch_map)
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_with_invalid_cert_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_multiple_invalid_authentication_attempts(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets and exchange invalid cert from CORD TESTER voltha test module acting as a subscriber for multiple times.
        4. Validate that eap tls with invalid cert auth packet is being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_with_no_cert_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "invalid_cert")
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "invalid_cert")
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "no_cert")
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT, cert_info = "invalid_cert")
            try:
                assert_equal(auth_status, True)
                assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_with_no_cert_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_with_aaa_app_deactivation(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls without sending client hello, it's not being exchanged between client, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_deactivating_app(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)

            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,"app_deactivate",))
            thread2 = threading.Thread(target = self.deactivate_apps, args = (aaa_app,))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Restart aaa app in onos during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_deactivating_app, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_radius_server(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls with restart of radius server and packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_restarting_radius(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)

            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,"restart_radius"))
            thread2 = threading.Thread(target = cord_test_radius_restart)
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Restart radius server during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_restarting_radius, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_with_disabled_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable olt which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_operating_olt_state(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)

            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "disable_olt_device",))
            thread2 = threading.Thread(target = self.voltha.disable_device, args = (device_id, False,))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Disable the ponsim olt device during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_operating_olt_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_disabling_uni_port(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable uni port which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_operating_olt_state(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)

            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "uni_port_admin_down",))
            thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Admin state of uni port is down and up after delay of 30 sec during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_operating_olt_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT +600)
    def test_subscriber_with_voltha_for_eap_tls_authentication_carrying_out_multiple_times_toggling_of_uni_port(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable uni port which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        10. Repeat steps from 3 to 9 for 10 times and finally verify tls flow

        """
        df = defer.Deferred()
        no_iterations = 10
        def tls_flow_check_with_disable_olt_device_scenario(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "uni_port_admin_down",))
                thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
                thread1.start()
                time.sleep(randint(1,2))
                log_test.info('Admin state of uni port is down and up after delay of 30 sec during tls auth flow check on voltha')
                thread2.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            time.sleep(60)
            cord_test_radius_restart()
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT)
            try:
        #        assert_equal(status, True)
                assert_equal(auth_status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_with_disable_olt_device_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart olt which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_operating_olt_state(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)

            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "restart_olt_device",))
            thread2 = threading.Thread(target = self.voltha.restart_device, args = (device_id,))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Restart the ponsim olt device during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_operating_olt_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_performing_multiple_times_restart_of_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart olt which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        10. Repeat steps from 3 to 9 for 10 times and finally verify tls flow
        """
        df = defer.Deferred()
        no_iterations = 10
        def tls_flow_check_with_disable_olt_device_scenario(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "restart_olt_device",))
                thread2 = threading.Thread(target = self.voltha.restart_device, args = (device_id,))
                thread1.start()
                time.sleep(randint(1,2))
                log_test.info('Restart the ponsim olt device during tls auth flow check on voltha')
                thread2.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            time.sleep(60)
            cord_test_radius_restart()
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT)
            try:
        #        assert_equal(status, True)
                assert_equal(auth_status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_with_disable_olt_device_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_onu(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart onu which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """
        df = defer.Deferred()
        def tls_flow_check_operating_onu_state(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "restart_onu_device",))
            thread2 = threading.Thread(target = self.voltha.restart_device, args = (onu_device_id,))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Restart the ponsim oon device during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_operating_onu_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_eap_tls_authentication_performing_multiple_times_restart_of_onu(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart onu which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        10. Repeat steps from 3 to 9 for 10 times and finally verify tls flow
        """
        df = defer.Deferred()
        no_iterations = 10
        def tls_flow_check_operating_olt_state(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT, "restart_onu_device",))
                thread2 = threading.Thread(target = self.voltha.restart_device, args = (onu_device_id,))
                thread1.start()
                time.sleep(randint(1,2))
                log_test.info('Restart the ponsim oon device during tls auth flow check on voltha')
                thread2.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            time.sleep(60)
            cord_test_radius_restart()
            auth_status = self.tls_flow_check(self.INTF_RX_DEFAULT)
            try:
        #        assert_equal(status, True)
                assert_equal(auth_status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_operating_olt_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between two subscriber, onos and freeradius.
        5. Verify that two subscribers are authenticated successfully.
        """

        df = defer.Deferred()
        def tls_flow_check_on_two_subscribers_same_olt_device(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Initiating tls auth packets from one more subscriber on same olt device which is deteced on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_on_two_subscribers_same_olt_device, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_eap_tls_authentication_using_same_certificates(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that two valid certificates are being exchanged between two subscriber, onos and freeradius.
        5. Verify that two subscribers are not authenticated.
        """

        df = defer.Deferred()
        def tls_flow_check_on_two_subscribers_same_olt_device(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_2_RX_DEFAULT, "same_cert",))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Initiating tls auth packets from one more subscriber on same olt device which is deteced on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                 assert_equal(self.success, True)
                 time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_on_two_subscribers_same_olt_device, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_eap_tls_authentication_initiating_invalid_tls_packets_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between valid subscriber, onos and freeradius.
        5. Validate that eap tls valid auth packets are being exchanged between invalid client, onos and freeradius.
        6. Verify that valid subscriber authenticated successfully.
        7. Verify that invalid subscriber are not authenticated successfully.
        """

        df = defer.Deferred()
        def tls_flow_check_on_two_subscribers_same_olt_device(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_2_RX_DEFAULT, "no_cert",))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Initiating tls auth packets from one more subscriber on same olt device which is deteced on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                 assert_equal(self.success, True)
                 time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_on_two_subscribers_same_olt_device, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_eap_tls_authentication_initiating_invalid_cert_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between valid subscriber, onos and freeradius.
        5. Validate that eap tls invalid cert auth packets are being exchanged between invalid subscriber, onos and freeradius.
        6. Verify that valid subscriber authenticated successfully.
        7. Verify that invalid subscriber are not authenticated successfully.
        """

        df = defer.Deferred()
        def tls_flow_check_on_two_subscribers_same_olt_device(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_2_RX_DEFAULT, "invalid_cert",))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Initiating tls auth packets from one more subscriber on same olt device which is deteced on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_on_two_subscribers_same_olt_device, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_eap_tls_authentication_with_one_uni_port_disabled(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between two subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable one of the uni port which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between one subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        10. Verify that other subscriber authenticated successfully.
        """

        df = defer.Deferred()
        def tls_flow_check_on_two_subscribers_same_olt_device(df):
            aaa_app = ["org.opencord.aaa"]
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            devices_list = self.voltha.get_devices()
            log_test.info('All available devices on voltha = %s'%devices_list['items'])

            onu_device_id = devices_list['items'][1]['id']
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            devices_list = self.voltha.get_devices()
            thread1 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.tls_flow_check, args = (self.INTF_2_RX_DEFAULT, "uni_port_admin_down",))
            thread1.start()
            time.sleep(randint(1,2))
            log_test.info('Initiating tls auth packets from one more subscriber on same olt device which is deteced on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
        #        assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)
        reactor.callLater(0, tls_flow_check_on_two_subscribers_same_olt_device, df)
        return df

    def test_3_subscribers_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue auth request packets from CORD TESTER voltha test module acting as multipe subscribers (3 subscribers)
        4. Validate that eap tls valid auth packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber is authenticated successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 3
        num_channels = 1
        services = ('TLS')
        cbs = (self.tls_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                      num_subscribers = num_subscribers,
                                      num_channels = num_channels)

    def test_5_subscribers_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue auth request packets from CORD TESTER voltha test module acting as multipe subscribers (5 subscriber)
        4. Validate that eap tls valid auth packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber is authenticated successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 5
        num_channels = 1
        services = ('TLS')
        cbs = (self.tls_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                      num_subscribers = num_subscribers,
                                      num_channels = num_channels)

    def test_9_subscribers_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue auth request packets from CORD TESTER voltha test module acting as multipe subscribers (9 subscriber)
        4. Validate that eap tls valid auth packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber is authenticated successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 9
        num_channels = 1
        services = ('TLS')
        cbs = (self.tls_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_request(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """

        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.remove_olt(switch_map)
                self.voltha.disable_device(device_id, delete = True)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_broadcast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac broadcast from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """

        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "invalid_src_mac_broadcast")
            try:
                assert_equal(dhcp_status, True)
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df


    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_multicast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac multicast from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """

        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "invalid_src_mac_multicast")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac zero from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "invalid_src_mac_junk")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_request_and_release(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp release from residential subscrber to dhcp server which is running as onos app.
        6  Verify that subscriber should not get ip from dhcp server, ping to gateway.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "request_release")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df


    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_starvation_positive_scenario(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times.
        6  Verify that subscriber should get ip from dhcp server.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "starvation_positive")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_starvation_negative_scenario(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber without of pool ip to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        5. Repeat steps 3 and 4 for 10 times.
        6  Verify that subscriber should not get ip from dhcp server.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "starvation_negative")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_sending_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Repeat step 3 for 50 times.
        6  Verify that subscriber should get same ip which was received from 1st discover from dhcp server.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "multiple_discover")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_sending_multiple_request(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send DHCP request to dhcp server which is running as onos app.
        6. Repeat step 5 for 50 times.
        7. Verify that subscriber should get same ip which was received from 1st discover from dhcp server.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "multiple_requests")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_requesting_desired_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired ip address from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip which was requested in step 3 from dhcp server successfully.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "desired_ip_address")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_requesting_desired_out_of_pool_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired out of pool ip address from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip which was requested in step 3 from dhcp server, and its offered only within dhcp pool of ip.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "desired_out_of_pool_ip_address")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_deactivating_dhcp_app_in_onos(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Deactivate dhcp server app in onos.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
        df = defer.Deferred()
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
            thread2 = threading.Thread(target = self.deactivate_apps, args = (dhcp_app,))
            log_test.info('Restart dhcp app in onos during client send discover to voltha')
            thread2.start()
            thread1.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_renew_time(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp renew packet to dhcp server which is running as onos app.
        6. Repeat step 4.
        """

        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "dhcp_renew")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_rebind_time(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp rebind packet to dhcp server which is running as onos app.
        6. Repeat step 4.
        """
        df = defer.Deferred()
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT, "dhcp_rebind")
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_toggling_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
        df = defer.Deferred()
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
            thread2 = threading.Thread(target = self.voltha.disable_device, args = (device_id,False,))
            log_test.info('Disable the olt device in during client send discover to voltha')
            thread2.start()
#            time.sleep(randint(0,1))
            thread1.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_with_multiple_times_disabling_of_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Repeat steps from 3 to 7 for 10 times and finally verify dhcp flow
        """
        df = defer.Deferred()
        no_iterations = 10
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
                thread2 = threading.Thread(target = self.voltha.disable_device, args = (device_id,False,))
                log_test.info('Disable the olt device in during client send discover to voltha')
                thread2.start()
#            time.sleep(randint(0,1))
                thread1.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            try:
                assert_equal(self.success, True)
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_toggling_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable olt devices which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """
        df = defer.Deferred()
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
            thread2 = threading.Thread(target = self.voltha.restart_device, args = (device_id,))
            thread2.start()
            thread1.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_toggling_olt_multiple_times(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable olt devices which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

        df = defer.Deferred()
        no_iterations = 10
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
                thread2 = threading.Thread(target = self.voltha.restart_device, args = (device_id,))
                thread2.start()
                thread1.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            try:
                assert_equal(dhcp_status, True)
                #assert_equal(status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_disabling_onu_port(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
        df = defer.Deferred()
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
            thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_disabling_onu_port_multiple_times(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
        df = defer.Deferred()
        no_iterations = 10
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
                thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
                thread1.start()
                thread2.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            try:
                #assert_equal(status, True)
                assert_equal(dhcp_status, True)
                assert_equal(self.success, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_toggling_onu_port(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable onu port which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

        df = defer.Deferred()
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
            thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
            log_test.info('Restart dhcp app in onos during client send discover to voltha')
            thread2.start()
            time.sleep(randint(0,1))
            thread1.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            assert_equal(dhcp_status, True)
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcp_toggling_onu_port_multiple_times(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable onu port which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

        df = defer.Deferred()
        no_iterations = 10
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            for i in range(no_iterations):
                thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT, "interrupting_dhcp_flows",))
                thread2 = threading.Thread(target = self.voltha_uni_port_toggle)
                log_test.info('Restart dhcp app in onos during client send discover to voltha')
                thread2.start()
                time.sleep(randint(0,1))
                thread1.start()
                time.sleep(10)
                thread1.join()
                thread2.join()
            dhcp_status = self.dhcp_flow_check(self.INTF_RX_DEFAULT)
            assert_equal(dhcp_status, True)
            try:
                assert_equal(self.success, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips from dhcp server successfully.
        """

        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
#                if self.success is not True:
                assert_equal(dhcp_flow_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times for both subscribers.
        6  Verify that subscribers should get same ips which are offered the first time from dhcp server.
        """


        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,"multiple_discover",))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,"multiple_discover",))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
#                if self.success is not True:
                assert_equal(dhcp_flow_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_and_with_multiple_discover_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times for only one subscriber and ping to gateway from other subscriber.
        6  Verify that subscriber should get same ip which is offered the first time from dhcp server and other subscriber ping to gateway should not failed
        """

        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,"multiple_discover",))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
#                if self.success is not True:
                assert_equal(dhcp_flow_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_discover_and_desired_ip_address_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from one residential subscriber to dhcp server which is running as onos app.
        3. Send dhcp request with desired ip from other residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips (one subscriber desired ip and other subscriber random ip) from dhcp server successfully.
        """

        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,"desired_ip_address",))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
#                if self.success is not True:
                assert_equal(dhcp_flow_status, True)
                #assert_equal(status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_discover_within_and_without_dhcp_pool_ip_addresses(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired wihtin dhcp pool ip from one residential subscriber to dhcp server which is running as onos app.
        3. Send dhcp request with desired without in dhcp pool ip from other residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips (both subscriber got random ips within dhcp pool) from dhcp server successfully.
        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,"desired_ip_address",))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,"desired_out_of_pool_ip_address",))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_disabling_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should not failed.
        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,"desired_ip_address",))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,"desired_out_of_pool_ip_address",))
            thread1.start()
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_toggling_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should not failed.
        8. Enable onu port on which was disable at step 5 and ping to gateway from other subscriber.
        9. Repeat step 3 and 4 for one subscriber where uni port is up now.
        10. Verify that subscriber should get ip from dhcp server and other subscriber ping to gateway should not failed.
        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread3 = threading.Thread(target = self.voltha_uni_port_toggle, args = (self.INTF_2_RX_DEFAULT,))
            thread1.start()
            thread2.start()
            thread3.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            thread3.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_disabling_olt(self):
        """
        Test Method: uni_port
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread3 = threading.Thread(target = self.voltha.disable_device, args = (device_id,False,))

            thread1.start()
            thread2.start()
            thread3.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            thread3.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_toggling_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        8. Enable the olt device which is detected in voltha.
        9. Verify that subscriber should get ip from dhcp server and other subscriber ping to gateway should not failed.

        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread3 = threading.Thread(target = self.voltha.restart_device, args = (device_id,))
            thread1.start()
            thread2.start()
            thread3.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            thread3.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_dhcp_with_paused_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Pause the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        """
        df = defer.Deferred()
        self.success = True
        dhcp_app =  'org.onosproject.dhcp'
        def dhcp_flow_check_scenario(df):
            log_test.info('Enabling ponsim_olt')
            ponsim_address = '{}:50060'.format(self.VOLTHA_HOST)
            device_id, status = self.voltha.enable_device('ponsim_olt', address = ponsim_address)
            assert_not_equal(device_id, None)
            voltha = VolthaCtrl(**self.voltha_attrs)
            time.sleep(10)
            switch_map = None
            olt_configured = False
            switch_map = voltha.config(fake = self.VOLTHA_CONFIG_FAKE)
            log_test.info('Installing OLT app')
            OnosCtrl.install_app(self.olt_app_file)
            time.sleep(5)
            log_test.info('Adding subscribers through OLT app')
            self.config_olt(switch_map)
            olt_configured = True
            time.sleep(5)
            thread1 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_RX_DEFAULT,))
            thread2 = threading.Thread(target = self.dhcp_flow_check, args = (self.INTF_2_RX_DEFAULT,))
            thread3 = threading.Thread(target = self.voltha.pause_device, args = (device_id,))
            thread1.start()
            thread2.start()
            thread3.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            thread3.join()
            dhcp_flow_status = self.success
            try:
                assert_equal(dhcp_flow_status, True)
                time.sleep(10)
            finally:
                self.voltha.disable_device(device_id, delete = True)
                self.remove_olt(switch_map)
            df.callback(0)

        reactor.callLater(0, dhcp_flow_check_scenario, df)
        return df

    def test_3_subscribers_with_voltha_for_dhcp_discover_requests(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (3 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 3
        num_channels = 1
        services = ('DHCP')
        cbs = (self.dhcp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_5_subscribers_with_voltha_for_dhcp_discover_requests(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (5 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 5
        num_channels = 1
        services = ('DHCP')
        cbs = (self.dhcp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_9_subscribers_with_voltha_for_dhcp_discover_requests(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (9 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 9 subscribers browsing 1 channels each"""
        num_subscribers = 9
        num_channels = 1
        services = ('DHCP')
        cbs = (self.dhcp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_3_subscribers_with_voltha_for_tls_auth_and_dhcp_discover_flows(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (3 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 3
        num_channels = 1
        services = ('TLS','DHCP')
        cbs = (self.tls_flow_check, self.dhcp_flow_check, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_5_subscribers_with_voltha_for_tls_auth_and_dhcp_discover_flows(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (5 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 5
        num_channels = 1
        services = ('TLS','DHCP')
        cbs = (self.tls_flow_check, self.dhcp_flow_check, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_9_subscribers_with_voltha_for_tls_auth_and_dhcp_discover_flows(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as multiple subscribers (9 subscribers)
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 9
        num_channels = 1
        services = ('TLS','DHCP')
        cbs = (self.tls_flow_check, self.dhcp_flow_check, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcprelay_request(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server successfully.
        """
        self.dhcprelay_setUpClass()
#       if not port_list:
        port_list = self.generate_port_list(1, 0)
        iface = self.port_map['ports'][port_list[1][1]]
        mac = self.get_mac(iface)
        self.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.default_config
        options = self.default_options
        subnet = self.default_subnet_config
        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv(mac=mac)
        self.dhcprelay_tearDwonClass()

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcprelay_request_with_invalid_broadcast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac broadcast from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    @deferred(TESTCASE_TIMEOUT)
    def test_subscriber_with_voltha_for_dhcprelay_request_with_invalid_multicast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac multicast from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcprelay_request_with_invalid_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac zero from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcprelay_request_and_release(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server successfully.
        5. Send dhcp release from residential subscrber to external dhcp server.
        6  Verify that subscriber should not get ip from external dhcp server, ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcprelay_starvation(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times.
        6  Verify that subscriber should get ip from external dhcp server..
        """

    def test_subscriber_with_voltha_for_dhcprelay_starvation_negative_scenario(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber without of pool ip to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server..
        5. Repeat steps 3 and 4 for 10 times.
        6  Verify that subscriber should not get ip from external dhcp server..
        """
    def test_subscriber_with_voltha_for_dhcprelay_sending_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Repeat step 3 for 50 times.
        6  Verify that subscriber should get same ip which was received from 1st discover from external dhcp server..
        """
    def test_subscriber_with_voltha_for_dhcprelay_sending_multiple_request(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send DHCP request to external dhcp server.
        6. Repeat step 5 for 50 times.
        7. Verify that subscriber should get same ip which was received from 1st discover from external dhcp server..
        """

    def test_subscriber_with_voltha_for_dhcprelay_requesting_desired_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired ip address from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip which was requested in step 3 from external dhcp server. successfully.
        """

    def test_subscriber_with_voltha_for_dhcprelay_requesting_desired_out_of_pool_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired out of pool ip address from residential subscriber to external dhcp server.
        4. Verify that subscriber should not get ip which was requested in step 3 from external dhcp server., and its offered only within dhcp pool of ip.
        """

    def test_subscriber_with_voltha_deactivating_dhcprelay_app_in_onos(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Deactivate dhcp server app in onos.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcprelay_renew_time(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send dhcp renew packet to external dhcp server.
        6. Repeat step 4.
        """

    def test_subscriber_with_voltha_for_dhcprelay_rebind_time(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send dhcp rebind packet to external dhcp server.
        6. Repeat step 4.
        """

    def test_subscriber_with_voltha_for_dhcprelay_disabling_olt(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcprelay_toggling_olt(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        8. Enable olt devices which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

    def test_subscriber_with_voltha_for_dhcprelay_disable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcprelay_disable_enable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        8. Enable onu port which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got different ips from external dhcp server. successfully.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times for both subscribers.
        6  Verify that subscribers should get same ips which are offered the first time from external dhcp server..
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_multiple_discover_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times for only one subscriber and ping to gateway from other subscriber.
        6  Verify that subscriber should get same ip which is offered the first time from external dhcp server. and other subscriber ping to gateway should not failed
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_discover_desired_ip_address_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from one residential subscriber to external dhcp server.
        3. Send dhcp request with desired ip from other residential subscriber to external dhcp server.
        4. Verify that subscribers had got different ips (one subscriber desired ip and other subscriber random ip) from external dhcp server. successfully.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_discover_for_in_range_and_out_of_range_from_dhcp_pool_ip_addresses(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired wihtin dhcp pool ip from one residential subscriber to external dhcp server.
        3. Send dhcp request with desired without in dhcp pool ip from other residential subscriber to external dhcp server.
        4. Verify that subscribers had got different ips (both subscriber got random ips within dhcp pool) from external dhcp server. successfully.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_disabling_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_toggling_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        8. Enable onu port on which was disable at step 5 and ping to gateway from other subscriber.
        9. Repeat step 3 and 4 for one subscriber where uni port is up now.
        10. Verify that subscriber should get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_disabling_olt(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_toggling_olt(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        8. Enable the olt device which is detected in voltha.
        9. Verify that subscriber should get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscribers_with_voltha_for_dhcprelay_with_paused_olt_detected(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Pause the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        """

    def test_subscriber_with_voltha_for_igmp_join_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA.
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        """

        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_leave_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA.
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port on ONU.
        6. Verify that multicast data packets are being recieved on join received uni port on ONU to cord-tester.
        7. Send igmp leave for a multicast group address multi-group-addressA.
        8. Verify that multicast data packets are not being recieved on leave sent uni port on ONU to cord-tester.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_leave_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_leave_and_again_join_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA.
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port on ONU.
        6. Verify that multicast data packets are being recieved on join received uni port on ONU to cord-tester.
        7. Send igmp leave for a multicast group address multi-group-addressA.
        8. Verify that multicast data packets are not being recieved on leave sent uni port on ONU to cord-tester.
        9. Repeat steps 4 to 6.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_leave_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_5_groups_joins_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for multicast group addresses multi-group-addressA,multi-group-addressB
        5. Send multicast data traffic for two groups (multi-group-addressA and multi-group-addressB) from other uni port on ONU.
        6. Verify that 2 groups multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 1
        num_channels = 5
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_5_groups_joins_and_leave_for_one_group_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for multicast group addresses multi-group-addressA,multi-group-addressB
        5. Send multicast data traffic for two groups (multi-group-addressA and multi-group-addressB) from other uni port on ONU.
        6. Verify that 2 groups multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send igmp leave for a multicast group address multi-group-addressA.
        8. Verify that multicast data packets of group(multi-group-addressA) are not being recieved on leave sent uni port on ONU to cord-tester.
        9. Verify that multicast data packets of group (multi-group-addressB) are being recieved on join sent uni port on ONU to cord-tester.
        """
        """Test subscriber join next for channel surfing with 3 subscribers browsing 3 channels each"""
        num_subscribers = 1
        num_channels = 5
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_join_different_group_src_list_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listB on ONU.
        8. Verify that multicast data packets are not being recieved on join sent uni port on ONU from other source list to cord-tester.
        """
        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['2.3.4.5','3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_change_to_exclude_mcast_group_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send igmp joins for a multicast group address multi-group-addressA with exclude source list src_listA
        8. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        9. Verify that multicast data packets are not being recieved on join sent uni port on ONU from other source list to cord-tester.
        """

        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_exclude, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['2.3.4.5','3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_change_to_include_back_from_exclude_mcast_group_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source exclude list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are not being recieved on join sent uni port on ONU to cord-tester.
        7. Send igmp joins for a multicast group address multi-group-addressA with allow source list src_listA
        8. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        9. Verify that multicast data packets are being recieved on join sent uni port on ONU from other source list to cord-tester.
        """
        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_exclude_again_include_back, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['2.3.4.5','3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_change_to_block_src_list_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send igmp joins for a multicast group address multi-group-addressA with block source list src_listA
        8. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        9. Verify that multicast data packets are not being recieved on join sent uni port on ONU from other source list to cord-tester.
        """

        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_block, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['2.3.4.5','3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_allow_new_src_list_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source exclude list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send igmp joins for a multicast group address multi-group-addressA with allow new source list src_listB
        8. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listB on ONU.
        9. Verify that multicast data packets are being recieved on join sent uni port on ONU from other source list to cord-tester.
        """

        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_block_again_allow_back, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['2.3.4.5','3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscriber_with_voltha_for_igmp_group_include_empty_src_list_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source exclude list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are not being recieved on join sent uni port on ONU to cord-tester.
        7. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listB on ONU.
        8. Verify that multicast data packets are not being recieved on join sent uni port on ONU from other source list to cord-tester.
        """

        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_group_include_source_empty_list, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['0'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_subscribers_with_voltha_for_igmp_group_exclude_empty_src_list_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA with source exclude list src_listA
        5. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listA on ONU.
        6. Verify that multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        7. Send multicast data traffic for a group (multi-group-addressA) from other uni port with source ip as src_listB on ONU.
        8. Verify that multicast data packets are being recieved on join sent uni port on ONU from other source list to cord-tester.
        """

        num_subscribers = 1
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_group_exclude_source_empty_list, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['0'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_two_subscribers_with_voltha_for_igmp_join_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressB from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """

        num_subscribers = 2
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['1.2.3.4'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_two_subscribers_with_voltha_for_igmp_join_leave_for_one_subscriber_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Send igmp leave for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        10. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """
        num_subscribers = 2
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_exclude, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['1.2.3.4','2.3.4.5'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_two_subscribers_with_voltha_for_igmp_leave_join_for_one_subscriber_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp leave for a multicast group address multi-group-addressB from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast group adress (multi-group-addressA) data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast group adress (multi-group-addressB) data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Send igmp join for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        10. Verify that multicast of group (multi-group-addressA) data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast of group (multi-group-addressA) data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Verify that multicast of group (multi-group-addressB) data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """

        num_subscribers = 2
        num_channels = 1
        services = ('IGMP')
        cbs = (self.igmp_flow_check_join_change_to_exclude_again_include_back, None, None)
        self.voltha_subscribers(services, cbs = cbs, src_list = ['1.2.3.4', '3.4.5.6'],
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_with_uni_port_down_for_one_subscriber_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable uni_2 port which is being shown on voltha CLI.
        10. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """
        #rx_port = self.port_map['ports'][port_list[i][1]]
        df = defer.Deferred()
        def igmp_flow_check_operating_onu_admin_state(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check_during_olt_onu_operational_issues, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

	    thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread2 = threading.Thread(target = self.voltha_uni_port_toggle, args = (self.port_map['ports'][port_list[1][1]],))
            thread1.start()
            time.sleep(randint(40,50))
            log_test.info('Admin state of uni port is down and up after delay of 30 sec during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, False)
                log_test.info('Igmp flow check expected to fail, hence ignore the test_status of igmp flow check')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_onu_admin_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_toggling_uni_port_for_one_subscriber_and_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable uni_2 port which is being shown on voltha CLI.
        10. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Enable uni_2 port which we disable at step 9.
        13. Repeat step 5,6 and 8.
        """
        df = defer.Deferred()
        def igmp_flow_check_operating_onu_admin_state(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread2 = threading.Thread(target = self.voltha_uni_port_toggle, args = (self.port_map['ports'][port_list[1][1]],))
            thread1.start()
            time.sleep(randint(50,60))
            log_test.info('Admin state of uni port is down and up after delay of 30 sec during tls auth flow check on voltha')
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                log_test.info('Igmp flow check expected to fail during UNI port down only, after UNI port is up it should be successful')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_onu_admin_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_disabling_olt_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable olt device which is being shown on voltha CLI.
        10. Verify that multicast data packets are not being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """
        df = defer.Deferred()
        def igmp_flow_check_operating_olt_admin_disble(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check_during_olt_onu_operational_issues, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(50,60))
            thread2 = threading.Thread(target = self.voltha.disable_device, args = (self.olt_device_id, False,))
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, False)
                log_test.info('Igmp flow check expected to fail during olt device is disabled, so ignored test_status of this test')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_olt_admin_disble, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_pausing_olt_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Pause olt device which is being shown on voltha CLI.
        10. Verify that multicast data packets are not being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        """
        df = defer.Deferred()
        def igmp_flow_check_operating_olt_admin_pause(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check_during_olt_onu_operational_issues, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(50,60))
            thread2 = threading.Thread(target = self.voltha.pause_device, args = (self.olt_device_id,))
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, False)
                log_test.info('Igmp flow check expected to fail during olt device is paused, so ignored test_status of this test')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_olt_admin_pause, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_toggling_olt_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable olt device which is being shown on voltha CLI.
        10. Verify that multicast data packets are not being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Enable olt device which is disable at step 9.
        13. Repeat steps 4,5, 7 and 8.
        """
        df = defer.Deferred()
        def igmp_flow_check_operating_olt_admin_restart(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(50,60))
            thread2 = threading.Thread(target = self.voltha.restart_device, args = (self.olt_device_id,))
            thread2.start()
            time.sleep(10)
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                log_test.info('Igmp flow check expected to fail during olt device restart, After OLT device is up, it should be successful')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_olt_admin_restart, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_multiple_times_disabling_olt_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable olt device which is being shown on voltha CLI.
        10. Verify that multicast data packets are not being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Repeat steps  4 to 11 steps multiple times (example 20 times)
        """
        df = defer.Deferred()
        no_iterations = 20
        def igmp_flow_check_operating_olt_admin_disble(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(30,40))
            for i in range(no_iterations):
                thread2 = threading.Thread(target = self.voltha.disable_device, args = (self.olt_device_id, False,))
                thread2.start()
                time.sleep(8)
                thread2.join()
            thread1.join()
            thread1.isAlive()
            thread2.join()
            try:
                assert_equal(self.success, False)
                log_test.info('Igmp flow check expected to fail during olt device is disabled, so ignored test_status of this test')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_olt_admin_disble, df)
        return df

    @deferred(TESTCASE_TIMEOUT + 200)
    def test_two_subscribers_with_voltha_for_igmp_multiple_times_toggling_uni_port_for_one_subscriber_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable uni_2 port which is being shown on voltha CLI.
        10. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Enable uni_2 port which we disable at step 9.
        13. Repeat step 5,6 and 8.
        14. Repeat steps  4 to 13 steps multiple times (example 5 times)
        """
        df = defer.Deferred()
        no_iterations = 5
        def igmp_flow_check_operating_onu_admin_state(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(40,60))
            for i in range(no_iterations):
                thread2 = threading.Thread(target = self.voltha_uni_port_toggle, args = (self.port_map['ports'][port_list[1][1]],))
                log_test.info('Admin state of uni port is down and up after delay of 30 sec during igmp flow check on voltha')
                thread2.start()
                time.sleep(1)
                thread2.join()
            thread1.isAlive()
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                log_test.info('Igmp flow check expected to fail during UNI port down only, after UNI port is up it should be successful')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_onu_admin_state, df)
        return df

    @deferred(TESTCASE_TIMEOUT)
    def test_two_subscribers_with_voltha_for_igmp_multiple_times_toggling_olt_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Issue dhcp client packets to get IP address from dhcp server for a subscriber and check connectivity.
        4. Send igmp joins for a multicast group address multi-group-addressA from one subscribers (uni_1 port)
        5. Send igmp joins for a multicast group address multi-group-addressA from other subscribers ( uni_2 port)
        6. Send multicast data traffic for a group (multi-group-addressA) from other uni_3 port on ONU.
        7. Verify that multicast data packets are being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        8. Verify that multicast data packets are being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        9. Disable olt device which is being shown on voltha CLI.
        10. Verify that multicast data packets are not being recieved on join sent uni (uni_1) port on ONU to cord-tester.
        11. Verify that multicast data packets are not being recieved on join sent uni (uni_2) port on ONU to cord-tester.
        12. Enable olt device which is disable at step 9.
        13. Repeat steps 4,5, 7 and 8.
        14. Repeat steps  4 to 13 steps multiple times (example 10 times)
        """
        df = defer.Deferred()
        no_iterations = 10
        def igmp_flow_check_operating_olt_admin_restart(df):
            num_subscribers = 2
            num_channels = 1
            services = ('IGMP')
            cbs = (self.igmp_flow_check, None, None)
            port_list = self.generate_port_list(num_subscribers, num_channels)

            thread1 = threading.Thread(target = self.voltha_subscribers, args = (services, cbs, 2, 1, ['1.2.3.4', '3.4.5.6'],))
            thread1.start()
            time.sleep(randint(50,60))
            for i in range(no_iterations):
                thread2 = threading.Thread(target = self.voltha.restart_device, args = (self.olt_device_id,))
                thread2.start()
                time.sleep(10)
                thread2.join()
            thread1.join()
            thread2.join()
            try:
                assert_equal(self.success, True)
                log_test.info('Igmp flow check expected to fail during olt device restart, after OLT device is up, it should be successful')
                time.sleep(10)
            finally:
                pass
            df.callback(0)
        reactor.callLater(0, igmp_flow_check_operating_olt_admin_restart, df)
        return df

    def test_5_subscriber_with_voltha_for_igmp_with_10_group_joins_verifying_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue multiple tls auth packets from CORD TESTER voltha test module acting as subscribers..
        3. Issue multiple dhcp client packets to get IP address from dhcp server for as subscribers and check connectivity.
        4. Send multiple igmp joins for 10 multicast group addresses multi-group-addressA,multi-group-addressB etc
        5. Send multicast data traffic for two groups (multi-group-addressA and multi-group-addressB) from other uni port on ONU.
        6. Verify that 2 groups multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        """

        num_subscribers = 5
        num_channels = 10
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)

    def test_9_subscriber_with_voltha_for_igmp_with_10_group_joins_and_verify_traffic(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue multiple tls auth packets from CORD TESTER voltha test module acting as subscribers..
        3. Issue multiple dhcp client packets to get IP address from dhcp server for subscribers and check connectivity.
        4. Send multiple igmp joins for 10 multicast group addresses multi-group-addressA,multi-group-addressB etc
        5. Send multicast data traffic for two groups (multi-group-addressA and multi-group-addressB) from other uni port on ONU.
        6. Verify that 2 groups multicast data packets are being recieved on join sent uni port on ONU to cord-tester.
        """
        num_subscribers = 9
        num_channels = 10
        services = ('IGMP')
        cbs = (self.igmp_flow_check, None, None)
        self.voltha_subscribers(services, cbs = cbs,
                                    num_subscribers = num_subscribers,
                                    num_channels = num_channels)
