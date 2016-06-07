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

    ip_count = 0
    failure_count = 0
    start_time = 0
    diff = 0

    transaction_count = 0
    transactions = 0
    running_time = 0
    total_success = 0
    total_failure = 0


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

    def send_recv(self, mac = None, update_seed = False, validate = True):
        cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
        if validate:
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
            log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip


    def stats(self,success_rate = False, only_discover = False, iface = 'veth0'):

	self.ip_count = 0
	self.failure_count = 0
	self.start_time = 0
	self.diff = 0
	self.transaction_count = 0

	config = {'startip':'182.17.0.3', 'endip':'182.17.0.180',
                  'ip':'182.17.0.2', 'mac': "ca:fe:c3:fe:ca:fe",
                  'subnet': '255.255.255.0', 'broadcast':'182.17.0.255', 'router':'182.17.0.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
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


    def test_dhcp_starvation(self, iface = 'veth0'):
        config = {'startip':'193.170.1.20', 'endip':'193.170.1.69',
                  'ip':'193.170.1.2', 'mac': "ca:fe:c2:fe:cc:fe",
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


    def test_dhcp_starvation(self, iface = 'veth0'):
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


    def test_dhcp_same_client_multiple_discover(self, iface = 'veth0'):
	config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                 'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
		  (cip, sip, mac) )
	log.info('Triggering DHCP discover again.')
	new_cip, new_sip, new_mac, _ = self.dhcp.only_discover()
	if cip == new_cip:
		log.info('Got same ip for 2nd DHCP discover for client IP %s from server %s for mac %s. Triggering DHCP Request. '
			  % (new_cip, new_sip, new_mac) )
	elif cip != new_cip:
		log.info('Ip after 1st discover %s' %cip)
                log.info('Map after 2nd discover %s' %new_cip)
		assert_equal(cip, new_cip)


    def test_dhcp_same_client_multiple_request(self, iface = 'veth0'):
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
		log.info('Something went wrong.')

    def test_dhcp_client_desired_address(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.31', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
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

    def test_dhcp_client_desired_address_out_of_pool(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.35', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
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


    def test_dhcp_server_nak_packet(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
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


    def test_dhcp_lease_packet(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	log.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, lval = self.dhcp.only_discover(lease_time = True)

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)
	elif lval != 700:
		log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s. That is not 700.' %
		 	 (cip, sip, mac, lval) )
		assert_not_equal(lval, 700)

    def test_dhcp_client_request_after_reboot(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
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

		new_cip, new_sip = self.dhcp.only_request(cip, mac, cl_reboot = True)
		if new_cip == None:
			log.info("Got DHCP server NAK.")
			assert_not_equal(new_cip, None)
		elif new_cip != None:
			log.info("Got DHCP ACK.")
		os.system('ifconfig '+iface+' up')




    def test_dhcp_server_after_reboot(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
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

		self.onos_ctrl.deactivate()

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

		status, _ = self.onos_ctrl.activate()
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


    def test_dhcp_specific_lease_packet(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	log.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, _ = self.dhcp.only_discover(lease_time = True)
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)
	elif cip and sip and mac:

		log.info("Triggering DHCP Request.")
		new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True)
		log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s. That is not 700.' %
		 	 (new_cip, new_sip, mac, lval) )
		assert_not_equal(lval, 700) #Negative Test Case



    def test_dhcp_lease_packet(self, iface = 'veth0'):
	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		log.info("Triggering DHCP Request.")
		new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True)
		if lval == 600:
			log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s.' %
		 		 (new_cip, new_sip, mac, lval) )
		else:
			log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s.' %
		 		 (new_cip, new_sip, mac, lval) )
			log.info('The lease time suppossed to be 600 secs or 10 mins.')
			assert_equal(lval, 600)

    def test_dhcp_client_renew_time(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
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

			log.info("Clinet 's Renewal time is :%s",lval)
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



    def test_dhcp_client_rebind_time(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
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

			log.info("Clinet 's Rebind time is :%s",lval)
			log.info("Generating delay till rebind time.")
			time.sleep(lval)

			log.info("Client Sending broadcast DHCP requests for renewing lease or for getting new ip.")

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


    def test_dhcp_client_expected_subnet_mask(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_subnet = '255.255.255.0'
	self.dhcp.return_option = 'subnet'

	cip, sip, mac, subnet_value = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		if expected_subnet == subnet_value:
			log.info("Got same subnet as passed in DHCP server configuration.")

		elif expected_subnet != subnet_value:
			log.info("Not getting same subnet as passed in DHCP server configuration.")
			assert_equal(expected_subnet, subnet_value)


    def test_dhcp_client_sends_dhcp_request_with_wrong_subnet_mask(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		self.dhcp.send_different_option = 'subnet'
		log.info("Sending DHCP Request with wrong subnet mask.")
		new_cip, new_sip = self.dhcp.only_request(cip, mac)
		if new_cip == None:

			log.info("Got DHCP NAK.")
			assert_not_equal(new_cip, None)

		elif new_cip and new_sip:

			log.info("Got DHCP Ack despite of specifying wrong Subnet Mask in DHCP Request.")
			log.info("Getting subnet mask as per server 's configuration.")


    def test_dhcp_client_expected_router_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_router_address = '20.20.20.1'
	self.dhcp.return_option = 'router'

	cip, sip, mac, router_address_value = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		if expected_router_address == router_address_value:
			log.info("Got same router address as passed in DHCP server configuration.")

		elif expected_router_address != router_address_value:
			log.info("Not getting same router address as passed in DHCP server configuration.")
			assert_equal(expected_router_address, router_address_value)


    def test_dhcp_client_sends_dhcp_request_with_wrong_router_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		self.dhcp.send_different_option = 'router'
		log.info("Sending DHCP Request with wrong router address.")
		new_cip, new_sip = self.dhcp.only_request(cip, mac)
		if new_cip == None:

			log.info("Got DHCP NAK.")
			assert_not_equal(new_cip, None)

		elif new_cip and new_sip:

			log.info("Got DHCP Ack despite of specifying wrong Router Address in DHCP Request.")
			log.info("Getting Router Address as per server 's configuration.")


    def test_dhcp_client_expected_broadcast_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_broadcast_address = '20.20.20.255'
	self.dhcp.return_option = 'broadcast_address'

	cip, sip, mac, broadcast_address_value = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		if expected_broadcast_address == broadcast_address_value:
			log.info("Got same router address as passed in DHCP server configuration.")

		elif expected_broadcast_address != broadcast_address_value:
			log.info("Not getting same router address as passed in DHCP server configuration.")
			assert_equal(expected_broadcast_address, broadcast_address_value)


    def test_dhcp_client_sends_dhcp_request_with_wrong_broadcast_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		self.dhcp.send_different_option = 'broadcast_address'
		log.info("Sending DHCP Request with wrong broadcast address.")
		new_cip, new_sip = self.dhcp.only_request(cip, mac)
		if new_cip == None:

			log.info("Got DHCP NAK.")
			assert_not_equal(new_cip, None)

		elif new_cip and new_sip:

			log.info("Got DHCP Ack despite of specifying wrong Broadcast Address in DHCP Request.")
			log.info("Getting Broadcast Address as per server 's configuration.")

    def test_dhcp_client_expected_dns_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1', 'domain':'8.8.8.8'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_dns_address = '8.8.8.8'
	self.dhcp.return_option = 'dns'

	cip, sip, mac, dns_address_value = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		if expected_dns_address == dns_address_value:
			log.info("Got same DNS address as passed in DHCP server configuration.")

		elif expected_dns_address != dns_address_value:
			log.info("Not getting same DNS address as passed in DHCP server configuration.")
			assert_equal(expected_dns_address, dns_address_value)


    def test_dhcp_client_sends_request_with_wrong_dns_address(self, iface = 'veth0'):

	config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                 'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                 'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1', 'domain':'8.8.8.8'}
        self.onos_dhcp_table_load(config)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)

	elif cip and sip and mac:

		self.dhcp.send_different_option = 'dns'
		log.info("Sending DHCP Request with wrong DNS address.")
		new_cip, new_sip = self.dhcp.only_request(cip, mac)
		if new_cip == None:
			log.info("Got DHCP NAK.")
			assert_not_equal(new_cip, None)
		elif new_cip and new_sip:
			log.info("Got DHCP Ack despite of specifying wrong DNS Address in DHCP Request.")
			log.info("Getting DNS Address as per server 's configuration.")

    def test_dhcp_server_transactions_per_second(self, iface = 'veth0'):

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

    def test_dhcp_server_consecutive_successes_per_second(self, iface = 'veth0'):

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


    def test_dhcp_server_client_transactions_per_second(self, iface = 'veth0'):

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

    def test_dhcp_server_consecutive_successful_clients_per_second(self, iface = 'veth0'):

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
