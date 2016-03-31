import unittest
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from scapy.all import *
import time
import copy
from DHCP import DHCPTest
from OnosCtrl import OnosCtrl
log.setLevel('INFO')

class dhcp_exchange(unittest.TestCase):

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
    
    app = 'org.onosproject.dhcp'

    def setUp(self):
        ''' Activate the dhcp app'''
        self.maxDiff = None ##for assert_equal compare outputs on failure
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)

    def teardown(self):
        '''Deactivate the dhcp app'''
        self.onos_ctrl.deactivate()

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

    def onos_dhcp_table_load(self, config = None):
          dhcp_dict = {'apps' : { 'org.onosproject.dhcp' : { 'dhcp' : copy.copy(self.dhcp_server_config) } } }
          dhcp_config = dhcp_dict['apps']['org.onosproject.dhcp']['dhcp']
          if config:
              for k in config.keys():
                  if dhcp_config.has_key(k):
                      dhcp_config[k] = config[k]
          self.onos_load_config(dhcp_dict)

    def send_recv(self, update_seed = False):
        cip, sip = self.dhcp.discover(update_seed = update_seed)
        assert_not_equal(cip, None)
        assert_not_equal(sip, None)
        log.info('Got dhcp client IP %s from server %s for mac %s' %
                 (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip

    def test_dhcp_1request(self, iface = 'veth0'):
        config = {'startip':'10.10.10.20', 'endip':'10.10.10.69', 
                  'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv()

    def test_dhcp_Nrequest(self, iface = 'veth0'):
        config = {'startip':'192.168.1.20', 'endip':'192.168.1.69', 
                  'ip':'192.168.1.2', 'mac': "ca:fe:ca:fe:cc:fe",
                  'subnet': '255.255.255.0', 'broadcast':'192.168.1.255', 'router': '192.168.1.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '192.169.1.1', iface = iface)
        ip_map = {}
        for i in range(10):
            cip, sip = self.send_recv(update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

    def test_dhcp_1release(self, iface = 'veth0'):
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

    def test_dhcp_Nrelease(self, iface = 'veth0'):
        config = {'startip':'192.170.1.20', 'endip':'192.170.1.30', 
                  'ip':'192.170.1.2', 'mac': "ca:fe:ca:fe:9a:fe",
                  'subnet': '255.255.255.0', 'broadcast':'192.170.1.255', 'router': '192.170.1.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = iface)
        ip_map = {}
        for i in range(10):
            cip, sip = self.send_recv(update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

        for ip in ip_map.keys():
            log.info('Releasing IP %s' %ip)
            assert_equal(self.dhcp.release(ip), True)

        ip_map2 = {}
        log.info('Triggering DHCP discover again after release')
        for i in range(len(ip_map.keys())):
            cip, sip = self.send_recv(update_seed = True)
            ip_map2[cip] = sip

        log.info('Verifying released IPs were given back on rediscover')
        if ip_map != ip_map2:
            log.info('Map before release %s' %ip_map)
            log.info('Map after release %s' %ip_map2)
        assert_equal(ip_map, ip_map2)
