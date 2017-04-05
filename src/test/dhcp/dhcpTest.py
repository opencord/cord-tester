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
import time
import copy
from DHCP import DHCPTest
from OltConfig import *
from OnosCtrl import OnosCtrl
from portmaps import g_subscriber_port_map
from CordLogger import CordLogger
from CordTestConfig import setup_module
log.setLevel('INFO')

class dhcp_exchange(CordLogger):

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

    STARTIP = "10.10.10.40"
    ENDIP = "10.10.10.41"
    IP = "10.10.10.2"
    MAC = "ca:fe:ca:fe:ca:fe"
    SUBNET = "255.255.255.0"
    BROADCAST = "10.10.10.255"
    ROUTER = "10.10.10.1"

    app = 'org.onosproject.dhcp'

    ip_count = 0
    failure_count = 0
    start_time = 0
    diff = 0

    transaction_count = 0
    transactions = 0
    running_time = 0
    total_success = 0
    total_failure = 0

    @classmethod
    def setUpClass(cls):
        cls.config_dhcp = {'startip': cls.STARTIP, 'endip': cls.ENDIP,
                           'ip':cls.IP, 'mac': cls.MAC, 'subnet': cls.SUBNET,
                           'broadcast':cls.BROADCAST, 'router':cls.ROUTER}
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        cls.iface = cls.port_map[1]

    def setUp(self):
        ''' Activate the dhcp app'''
        super(dhcp_exchange, self).setUp()
        self.maxDiff = None ##for assert_equal compare outputs on failure
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)

    def tearDown(self):
        '''Deactivate the dhcp app'''
        self.onos_ctrl.deactivate()
        super(dhcp_exchange, self).tearDown()

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

    def send_recv(self, mac = None, update_seed = False, validate = True):
        cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
        log.info("discover cip %s"%(cip))
        log.info("discover sip %s"%(sip))
        if validate:
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
            log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip

    def stats(self,success_rate = False, only_discover = False):

	self.ip_count = 0
	self.failure_count = 0
	self.start_time = 0
	self.diff = 0
	self.transaction_count = 0
	config = {'startip':'182.17.0.3', 'endip':'182.17.0.180',
                  'ip':'182.17.0.2', 'mac': "ca:fe:c3:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'182.17.0.255', 'router':'182.17.0.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = self.iface)
	self.start_time = time.time()

	while self.diff <= 60:
	    if only_discover:
		cip, sip, mac, _ = self.dhcp.only_discover(multiple = True)
                log.info('Got dhcp client IP %s from server %s for mac %s' %
                          (cip, sip, mac))
            else:
                cip, sip = self.send_recv(update_seed = True, validate = False)

	    if cip:
	    	self.ip_count +=1
	    elif cip == None:
		self.failure_count += 1
                log.info('Failed to get ip')
		if success_rate and self.ip_count > 0:
		   break
	    self.diff = round(time.time() - self.start_time, 0)


	self.transaction_count = round((self.ip_count+self.failure_count)/self.diff, 2)

    	self.transactions += (self.ip_count+self.failure_count)
	self.running_time += self.diff
        self.total_success += self.ip_count
	self.total_failure += self.failure_count

    def test_dhcp_1request(self):
        self.onos_dhcp_table_load(self.config_dhcp)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
        self.send_recv()

    def test_dhcp_1request_with_invalid_source_mac_broadcast(self):
        config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                  'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac='ff:ff:ff:ff:ff:ff')
	assert_equal(cip,None)
	log.info('ONOS dhcp server rejected client discover with invalid source mac as expected')

    def test_dhcp_1request_with_invalid_source_mac_multicast(self):
        config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                  'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac='01:80:c2:91:02:e4')
        assert_equal(cip,None)
        log.info('ONOS dhcp server rejected client discover with invalid source mac as expected')

    def test_dhcp_1request_with_invalid_source_mac_zero(self):
        config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                  'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac='00:00:00:00:00:00')
        assert_equal(cip,None)
        log.info('ONOS dhcp server rejected client discover with invalid source mac as expected')

    def test_dhcp_Nrequest(self, requests=10):
        config = {'startip':'192.168.1.20', 'endip':'192.168.1.69',
                  'ip':'192.168.1.2', 'mac': "ca:fe:ca:fe:cc:fe",
                  'subnet': '255.255.255.0', 'broadcast':'192.168.1.255', 'router': '192.168.1.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '192.168.1.1', iface = self.iface)
        ip_map = {}
        for i in range(requests):
            cip, sip = self.send_recv(update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

    def test_dhcp_1release(self):
        config = {'startip':'10.10.100.20', 'endip':'10.10.100.230',
                  'ip':'10.10.100.2', 'mac': "ca:fe:ca:fe:8a:fe",
                  'subnet': '255.255.255.0', 'broadcast':'10.10.100.255', 'router':'10.10.100.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = self.iface)
        cip, sip = self.send_recv()
        log.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcp.release(cip), True)
        log.info('Triggering DHCP discover again after release')
        cip2, sip2 = self.send_recv(update_seed = True)
        log.info('Verifying released IP was given back on rediscover')
        assert_equal(cip, cip2)
        log.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
        assert_equal(self.dhcp.release(cip2), True)

    def test_dhcp_Nrelease(self):
        config = {'startip':'192.170.1.20', 'endip':'192.170.1.230',
                  'ip':'192.170.1.2', 'mac': "ca:fe:ca:fe:9a:fe",
                  'subnet': '255.255.255.0', 'broadcast':'192.170.1.255', 'router': '192.170.1.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = self.iface)
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


    def test_dhcp_starvation_positive_scenario(self):
        config = {'startip':'193.170.1.20', 'endip':'193.170.1.69',
                  'ip':'193.170.1.2', 'mac': "ca:fe:c2:fe:cc:fe",
                  'subnet': '255.255.255.0', 'broadcast':'192.168.1.255', 'router': '192.168.1.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '192.169.1.1', iface = self.iface)
        ip_map = {}
        for i in range(10):
            cip, sip = self.send_recv(update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip


    def test_dhcp_starvation_negative_scenario(self):
        config = {'startip':'182.17.0.20', 'endip':'182.17.0.69',
                  'ip':'182.17.0.2', 'mac': "ca:fe:c3:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'182.17.0.255', 'router':'182.17.0.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = self.iface)
        log.info('Verifying passitive case')
        for x in xrange(50):
            mac = RandMAC()._fix()
            self.send_recv(mac = mac)
        log.info('Verifying negative case')
        cip, sip = self.send_recv(update_seed = True, validate = False)
        assert_equal(cip, None)
        assert_equal(sip, None)


    def test_dhcp_same_client_multiple_discover(self):
	config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                 'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	log.info('Triggering DHCP discover again.')
	new_cip, new_sip, new_mac, _ = self.dhcp.only_discover()
	assert_equal(new_cip, cip)
	log.info('client got same IP as expected when sent 2nd discovery')


    def test_dhcp_same_client_multiple_request(self):
	config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                 'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = self.iface)
	log.info('Sending DHCP discover and DHCP request.')
	cip, sip = self.send_recv()
	mac = self.dhcp.get_mac(cip)[0]
	log.info("Sending DHCP request again.")
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip,cip)
	log.info('server offered same IP to clain for multiple requests, as expected')

    def test_dhcp_client_desired_address(self):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.50', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
	assert_not_equal(cip, None)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac))
	assert_equal(cip,self.dhcp.seed_ip)
	log.info('ONOS dhcp server offered client requested IP %s as expected'%self.dhcp.seed_ip)

    #test failing, server not returns NAK when requested out of pool IP
    def test_dhcp_client_desired_address_out_of_pool(self):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.75', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
	assert_not_equal(cip, None)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,self.dhcp.seed_ip)
	log.info('server offered IP from its pool of IPs when requested out of pool IP, as expected')


    def test_dhcp_server_nak_packet(self):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request('20.20.20.31', mac)
        assert_equal(new_cip, None)  #Negative Test Case
	log.info('dhcp servers sent NAK as expected when requested different IP from  same client')


    #test_dhcp_lease_packet
    def test_dhcp_client_requests_specific_lease_time_in_discover(self,lease_time = 700):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	self.dhcp.return_option = 'lease'
	log.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, lval = self.dhcp.only_discover(lease_time = True, lease_value = lease_time)
        assert_equal(lval, 700)
	log.info('dhcp server offered IP address with client requested lease  time')

    def test_dhcp_client_request_after_reboot(self):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	log.info('verifying client IP after reboot')
	os.system('ifconfig '+self.iface+' down')
	time.sleep(5)
	os.system('ifconfig '+self.iface+' up')
	new_cip, new_sip = self.dhcp.only_request(cip, mac, cl_reboot = True)
	assert_equal(new_cip,cip)
	log.info('client got same ip after reboot, as expected')


    def test_dhcp_server_after_reboot(self):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	self.onos_ctrl.deactivate()
	new_cip1, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip1,None)
	status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
	time.sleep(3)
	new_cip2, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip2,cip)
	log.info('client got same ip after server reboot, as expected')

    def test_dhcp_specific_lease_time_only_in_discover_but_not_in_request_packet(self,lease_time=700):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	log.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, _ = self.dhcp.only_discover(lease_time = True,lease_value=lease_time)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True)
	assert_equal(new_cip,cip)
	assert_not_equal(lval, lease_time) #Negative Test Case
	log.info('client requested lease time only in discover but not in request, not seen in server ACK packet as expected')


    def test_dhcp_specific_lease_time_only_in_request_but_not_in_discover_packet(self,lease_time=800):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True, lease_value=lease_time)
	assert_equal(lval, lease_time)
	log.info('client requested lease time in request packet, seen in server ACK packet as expected')

    def test_dhcp_client_renew_time(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
	log.info('waiting renew  time %d seconds to send next request packet'%lval)
	time.sleep(lval)
	latest_cip, latest_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
	assert_equal(latest_cip,cip)
	log.info('client got same IP after renew time, as expected')

    def test_dhcp_client_rebind_time(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, rebind_time = True)
	log.info('waiting rebind time %d seconds to send next request packet'%lval)
	time.sleep(lval)
	latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac)
	assert_equal(latest_cip,cip)
	log.info('client got same IP after rebind time, as expected')

    def test_dhcp_client_expected_subnet_mask(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	expected_subnet = '255.255.255.0'
	self.dhcp.return_option = 'subnet'
	cip, sip, mac, subnet_mask = self.dhcp.only_discover()
	assert_equal(subnet_mask, expected_subnet)
	assert_not_equal(cip, None)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	log.info('seen expected subnet mask %s in dhcp offer packet'%subnet_mask)

    def test_dhcp_client_sends_dhcp_request_with_wrong_subnet_mask(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	self.dhcp.send_different_option = 'subnet'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log.info("Got DHCP Ack despite of specifying wrong Subnet Mask in DHCP Request.")


    def test_dhcp_client_expected_router_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	expected_router_address = '20.20.20.1'
	self.dhcp.return_option = 'router'

	cip, sip, mac, router_address_ip = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	assert_equal(expected_router_address, router_address_ip)
	log.info('seen expected rouer address %s ip in dhcp offer packet'%router_address_ip)

    def test_dhcp_client_sends_dhcp_request_with_wrong_router_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	self.dhcp.send_different_option = 'router'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log.info("Got DHCP Ack despite of specifying wrong Router Address in DHCP Request.")


    def test_dhcp_client_expected_broadcast_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	expected_broadcast_address = '20.20.20.255'
	self.dhcp.return_option = 'broadcast_address'

	cip, sip, mac, broadcast_address = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	assert_equal(expected_broadcast_address, broadcast_address)
	log.info('seen expected broadcast address %s in dhcp offer packet'%broadcast_address)

    def test_dhcp_client_sends_dhcp_request_with_wrong_broadcast_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	self.dhcp.send_different_option = 'broadcast_address'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log.info("Got DHCP Ack despite of specifying wrong Broadcast Address in DHCP Request.")

    def test_dhcp_client_expected_dns_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1', 'domain':'8.8.8.8'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)
	expected_dns_address = '8.8.8.8'
	self.dhcp.return_option = 'dns'

	cip, sip, mac, dns_address = self.dhcp.only_discover()
	assert_not_equal(cip, None)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_dns_address, dns_address)
	log.info('seen expected DNS ip address %s in dhcp offer packet'%dns_address)

    def test_dhcp_client_sends_request_with_wrong_dns_address(self):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1', 'domain':'8.8.8.8'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = self.iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	assert_not_equal(cip, None)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	self.dhcp.send_different_option = 'dns'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log.info("Got DHCP Ack despite of specifying wrong DNS Address in DHCP Request.")

    def test_dhcp_server_transactions_per_second(self):

	for i in range(1,4):
		self.stats()
		log.info("Stats for run %d",i)
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	        log.info("    %d                    %d                     %d                  %d" %(self.ip_count+self.failure_count, 		               self.ip_count, self.failure_count, self.diff))
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of transactions per second in run %d:%f" %(i, self.transaction_count))

	log.info("Final Statistics for total transactions")
	log.info("----------------------------------------------------------------------------------")
	log.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))
	log.info("----------------------------------------------------------------------------------")
	log.info("Average no. of transactions per second: %d", round(self.transactions/self.running_time,0))

    def test_dhcp_server_consecutive_successes_per_second(self):

	for i in range(1,4):
		self.stats(success_rate = True)
		log.info("Stats for run %d",i)
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of consecutive successful transactions          Running Time ")
	        log.info("                   %d                                   %d        " %(self.ip_count, self.diff))
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of successful transactions per second in run %d:%f" %(i, self.transaction_count))
		log.info("----------------------------------------------------------------------------------")

	log.info("Final Statistics for total successful transactions")
	log.info("----------------------------------------------------------------------------------")
	log.info("Total transactions     Total No. of consecutive successes         Running Time ")
	log.info("    %d                                 %d                             %d        " %(self.transactions,
                 self.total_success, self.running_time))
	log.info("----------------------------------------------------------------------------------")
	log.info("Average no. of consecutive successful transactions per second: %d", round(self.total_success/self.running_time,0))
	log.info("----------------------------------------------------------------------------------")


    def test_dhcp_server_client_transactions_per_second(self):

        for i in range(1,4):
		self.stats(only_discover = True)
		log.info("----------------------------------------------------------------------------------")
		log.info("Stats for run %d of sending only DHCP Discover",i)
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	        log.info("    %d                    %d                     %d                  %d" %(self.ip_count+self.failure_count, 		               self.ip_count, self.failure_count, self.diff))
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of clients per second in run %d:%f                                      "
			%(i, self.transaction_count))
		log.info("----------------------------------------------------------------------------------")
	log.info("Final Statistics for total transactions of sending only DHCP Discover")
	log.info("----------------------------------------------------------------------------------")
	log.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))
	log.info("----------------------------------------------------------------------------------")
	log.info("Average no. of clients per second: %d                                        ",
		round(self.transactions/self.running_time,0))
	log.info("----------------------------------------------------------------------------------")

    def test_dhcp_server_consecutive_successful_clients_per_second(self):

        for i in range(1,4):
		self.stats(success_rate = True, only_discover = True)
		log.info("----------------------------------------------------------------------------------")
		log.info("Stats for run %d for sending only DHCP Discover",i)
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of consecutive successful transactions          Running Time ")
	        log.info("                   %d                                   %d        " %(self.ip_count, self.diff))
		log.info("----------------------------------------------------------------------------------")
		log.info("No. of consecutive successful clients per second in run %d:%f" %(i, self.transaction_count))
		log.info("----------------------------------------------------------------------------------")

	log.info("Final Statistics for total successful transactions")
	log.info("----------------------------------------------------------------------------------")
	log.info("Total transactions     Total No. of consecutive successes         Running Time ")
	log.info("    %d                                 %d                             %d        " %(self.transactions,
                 self.total_success, self.running_time))
	log.info("----------------------------------------------------------------------------------")
	log.info("Average no. of consecutive successful clients per second: %d", round(self.total_success/self.running_time,0))
	log.info("----------------------------------------------------------------------------------")

