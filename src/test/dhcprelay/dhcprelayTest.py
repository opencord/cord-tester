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
import os, sys
from DHCP import DHCPTest
from OnosCtrl import OnosCtrl, get_mac
from OltConfig import OltConfig
from CordTestServer import cord_test_onos_restart
from CordLogger import CordLogger
from portmaps import g_subscriber_port_map
import threading, random
from threading import current_thread
log.setLevel('INFO')

class dhcprelay_exchange(CordLogger):

    app = 'org.onosproject.dhcprelay'
    app_dhcp = 'org.onosproject.dhcp'
    relay_interfaces_last = ()
    interface_to_mac_map = {}
    host_ip_map = {}
    test_path = os.path.dirname(os.path.realpath(__file__))
    dhcp_data_dir = os.path.join(test_path, '..', 'setup')
    olt_conf_file = os.path.join(test_path, '..', 'setup/olt_config.json')
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

    lock = threading.Condition()
    ip_count = 0
    failure_count = 0
    start_time = 0
    diff = 0

    transaction_count = 0
    transactions = 0
    running_time = 0
    total_success = 0
    total_failure = 0
    #just in case we want to reset ONOS to default network cfg after relay tests
    onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))
    configs = {}

    @classmethod
    def setUpClass(cls):
        ''' Activate the dhcprelay app'''
        OnosCtrl(cls.app_dhcp).deactivate()
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.app)
        status, _ = cls.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)
        cls.dhcp_relay_setup()
        ##start dhcpd initially with default config
        cls.dhcpd_start()

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the dhcp relay app'''
        try:
            os.unlink('{}/dhcpd.conf'.format(cls.dhcp_data_dir))
            os.unlink('{}/dhcpd.leases'.format(cls.dhcp_data_dir))
        except: pass
        cls.onos_ctrl.deactivate()
        cls.dhcpd_stop()
        cls.dhcp_relay_cleanup()

    @classmethod
    def dhcp_relay_setup(cls):
        did = OnosCtrl.get_device_id()
        cls.relay_device_id = did
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, _ = cls.olt.olt_port_map()
        if cls.port_map:
            ##Per subscriber, we use 1 relay port
            try:
                relay_port = cls.port_map[cls.port_map['relay_ports'][0]]
            except:
                relay_port = cls.port_map['uplink']
            cls.relay_interface_port = relay_port
            cls.relay_interfaces = (cls.port_map[cls.relay_interface_port],)
        else:
            cls.relay_interface_port = 100
            cls.relay_interfaces = (g_subscriber_port_map[cls.relay_interface_port],)
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
    def dhcp_relay_cleanup(cls):
        ##reset the ONOS port configuration back to default
        for config in cls.configs.items():
            OnosCtrl.delete(config)
        # if cls.onos_restartable is True:
        #     log.info('Cleaning up dhcp relay config by restarting ONOS with default network cfg')
        #     return cord_test_onos_restart(config = {})

    @classmethod
    def onos_load_config(cls, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

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
        log.info('Starting DHCPD server with command: %s' %dhcpd_cmd)
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

    def stats(self,success_rate = False, only_discover = False, iface = 'veth0'):

	self.ip_count = 0
	self.failure_count = 0
	self.start_time = 0
	self.diff = 0
	self.transaction_count = 0

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
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
	self.start_time = time.time()

	while self.diff <= 60:

	    if only_discover:
		cip, sip, mac, _ = self.dhcp.only_discover(multiple = True)
                log.info('Got dhcp client IP %s from server %s for mac %s' %
                        (cip, sip, mac))
	    else:
	        cip, sip = self.send_recv(mac, update_seed = True, validate = False)

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

    def send_recv(self, mac, update_seed = False, validate = True):
        cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
        if validate:
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
        log.info('Got dhcp client IP %s from server %s for mac %s' %
                (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip

    def test_dhcpRelay_1request(self, iface = 'veth0'):
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
        self.send_recv(mac)

    def test_dhcpRelay_Nrequest(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '192.169.1.1', iface = iface)
        ip_map = {}
        for i in range(10):
            mac = RandMAC()._fix()
            cip, sip = self.send_recv(mac, update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

    def test_dhcpRelay_1release(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = iface)
        cip, sip = self.send_recv(mac)
        log.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcp.release(cip), True)
        log.info('Triggering DHCP discover again after release')
        cip2, sip2 = self.send_recv(mac)
        log.info('Verifying released IP was given back on rediscover')
        assert_equal(cip, cip2)
        log.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
        assert_equal(self.dhcp.release(cip2), True)

    def test_dhcpRelay_Nrelease(self, iface = 'veth0'):
        mac = None
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
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = iface)
        ip_map = {}
        for i in range(10):
            cip, sip = self.send_recv(mac, update_seed = True)
            if ip_map.has_key(cip):
                log.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

        for ip in ip_map.keys():
            log.info('Releasing IP %s' %ip)
            assert_equal(self.dhcp.release(ip), True)

        ip_map2 = {}
        log.info('Triggering DHCP discover again after release')
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = iface)
        for i in range(len(ip_map.keys())):
            cip, sip = self.send_recv(mac, update_seed = True)
            ip_map2[cip] = sip

        log.info('Verifying released IPs were given back on rediscover')
        if ip_map != ip_map2:
            log.info('Map before release %s' %ip_map)
            log.info('Map after release %s' %ip_map2)
        assert_equal(ip_map, ip_map2)

    def test_dhcpRelay_starvation(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
        log.info('Verifying 1 ')
        while True:
            mac = RandMAC()._fix()
            cip, sip = self.send_recv(mac = mac, validate = False)
	    if cip is None:
		break
        log.info('Verifying 2 ')
        cip, sip = self.send_recv(mac, update_seed = True, validate = False)
        assert_equal(cip, None)
        assert_equal(sip, None)

    def test_dhcpRelay_same_client_multiple_discover(self, iface = 'veth0'):
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


    def test_dhcpRelay_same_client_multiple_request(self, iface = 'veth0'):
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
	log.info('Sending DHCP discover and DHCP request.')
	cip, sip = self.send_recv(mac)
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

    def test_dhcpRelay_client_desired_address(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '192.168.1.31', iface = iface)
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

    def test_dhcpRelay_client_desired_address_out_of_pool(self, iface = 'veth0'):
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


    def test_dhcpRelay_nak_packet(self, iface = 'veth0'):
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


    def test_dhcpRelay_specific_lease_packet(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()

	log.info("Verifying Client 's IP and mac in DHCP Offer packet. Those should not be none, which is expected.")
	if (cip == None and mac != None):
		log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
		assert_not_equal(cip, None)
	elif cip != None:
		self.dhcp.specific_lease = 800
		log.info('Sending DHCP request with specific lease time of %s', self.dhcp.specific_lease)
		new_cip, new_sip, lval = self.dhcp.only_request(cip, mac)
		if new_cip == None:

			log.info("Got DHCP server NAK.")
			assert_equal(new_cip, None)  #Negative Test Case
		assert_equal(lval, self.dhcp.specific_lease)

    def test_dhcpRelay_client_request_after_reboot(self, iface = 'veth0'):
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

    def test_dhcpRelay_after_reboot(self, iface = 'veth0'):
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

		self.tearDownClass()

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

		self.setUpClass()

		for i in range(0,4):
			log.info("Sending DHCP Request after DHCP server is up.")
			log.info('')
			new_cip, new_sip = self.dhcp.only_request(cip, mac)
			if new_cip == None and new_sip == None:
				log.info('')
				log.info("DHCP Request timed out.")
			elif new_cip and new_sip:
				log.info("Got Reply from DHCP server.")
				assert_equal(new_cip, cip)


    def test_dhcpRelay_specific_lease_packet_in_dhcp_discover(self, iface = 'veth0'):
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



    def test_dhcpRelay_default_lease_time(self, iface = 'veth0'):
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
			log.info('Getting dhcp client IP %s from server %s for mac %s with defualt lease time %s.' %
                                (new_cip, new_sip, mac, lval) )
		else:
			log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s.' %
                                (new_cip, new_sip, mac, lval) )
			log.info('The lease time suppossed to be 600 secs or 10 mins.')
			assert_equal(lval, 600)

    def test_dhcpRelay_client_renew_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.default_config
	new_options = [('dhcp-renewal-time', 300), ('dhcp-rebinding-time', 525)]
        options = self.default_options + new_options
        subnet = self.default_subnet_config
        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)
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



    def test_dhcpRelay_client_rebind_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.default_config
	new_options = [('dhcp-renewal-time', 300), ('dhcp-rebinding-time', 525)]
        options = self.default_options + new_options
        subnet = self.default_subnet_config
        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)
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


    def test_dhcpRelay_client_expected_subnet_mask(self, iface = 'veth0'):
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


    def test_dhcpRelay_client_sends_dhcp_request_with_wrong_subnet_mask(self, iface = 'veth0'):
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


    def test_dhcpRelay_client_expected_router_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.default_config
        config = self.default_config
	new_options = [('routers', '20.20.20.1')]
        options = self.default_options + new_options
        subnet = self.default_subnet_config
        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)
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


    def test_dhcpRelay_client_sends_dhcp_request_with_wrong_router_address(self, iface = 'veth0'):
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


    def test_dhcpRelay_client_expected_broadcast_address(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_broadcast_address = '192.168.1.255'
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


    def test_dhcpRelay_client_sends_dhcp_request_with_wrong_broadcast_address(self, iface = 'veth0'):
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

    def test_dhcpRelay_client_expected_dns_address(self, iface = 'veth0'):
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
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_dns_address = '192.168.1.1'
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


    def test_dhcpRelay_client_sends_request_with_wrong_dns_address(self, iface = 'veth0'):
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

    def test_dhcpRelay_transactions_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.stats()
	    log.info("Statistics for run %d",i)
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

    def test_dhcpRelay_consecutive_successes_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.stats(success_rate = True)
	    log.info("Statistics for run %d",i)
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


    def test_dhcpRelay_clients_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.stats(only_discover = True)
	    log.info("----------------------------------------------------------------------------------")
	    log.info("Statistics for run %d of sending only DHCP Discover",i)
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

    def test_dhcpRelay_consecutive_successful_clients_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.stats(success_rate = True, only_discover = True)
	    log.info("----------------------------------------------------------------------------------")
	    log.info("Statistics for run %d for sending only DHCP Discover",i)
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

    def test_dhcpRelay_concurrent_transactions_per_second(self, iface = 'veth0'):

        config = self.default_config
        options = self.default_options
        subnet =  [ ('192.168.1.2',
'''
subnet 192.168.0.0 netmask 255.255.0.0 {
    range 192.168.1.10 192.168.2.100;
}
'''), ]

        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)

	for key in (key for key in g_subscriber_port_map if key < 100):
	    self.host_load(g_subscriber_port_map[key])

	def thread_fun(i):
	    mac = self.get_mac('veth{}'.format(i))
	    cip, sip = DHCPTest(iface = 'veth{}'.format(i)).discover(mac = mac)
	    log.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
	    self.lock.acquire()

	    if cip:
		    self.ip_count += 1

	    elif cip is None:
		    self.failure_count += 1

	    self.lock.notify_all()
	    self.lock.release()

	for i in range (1,4):
	    self.ip_count = 0
	    self.failure_count = 0
	    self.start_time = 0
	    self.diff = 0
	    self.transaction_count = 0
	    self.start_time = time.time()

	    while self.diff <= 60:
		  t = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(0, random.randrange(1,40,1), 1)})
		  t1 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(42, random.randrange(43,80,1), 1)})
		  t2 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(82, random.randrange(83,120,1), 1)})
		  t3 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(122, random.randrange(123,160,1), 1)})
		  t4 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(162, random.randrange(163,180,1), 1)})
		  t5 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(182, random.randrange(183,196,1), 1)})

		  t.start()
		  t1.start()
		  t2.start()
		  t3.start()
		  t4.start()
		  t5.start()

		  t.join()
		  t1.join()
		  t2.join()
		  t3.join()
		  t4.join()
		  t5.join()

		  self.diff = round(time.time() - self.start_time, 0)

	    self.transaction_count = round((self.ip_count+self.failure_count)/self.diff, 2)

	    self.transactions += (self.ip_count+self.failure_count)
	    self.running_time += self.diff
	    self.total_success += self.ip_count
	    self.total_failure += self.failure_count


	    log.info("----------------------------------------------------------------------------------")
	    log.info("Statistics for run %d",i)
	    log.info("----------------------------------------------------------------------------------")
	    log.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	    log.info("    %d                    %d                     %d                  %d"
			    %(self.ip_count+self.failure_count,self.ip_count, self.failure_count, self.diff))
	    log.info("----------------------------------------------------------------------------------")
	    log.info("No. of transactions per second in run %d:%f" %(i, self.transaction_count))
	    log.info("----------------------------------------------------------------------------------")

	log.info("----------------------------------------------------------------------------------")
	log.info("Final Statistics for total transactions")
	log.info("----------------------------------------------------------------------------------")
	log.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))

	log.info("----------------------------------------------------------------------------------")
	log.info("Average no. of transactions per second: %d", round(self.transactions/self.running_time,0))
	log.info("----------------------------------------------------------------------------------")

    def test_dhcpRelay_concurrent_consecutive_successes_per_second(self, iface = 'veth0'):

        config = self.default_config
        options = self.default_options
        subnet =  [ ('192.168.1.2',
'''
subnet 192.168.0.0 netmask 255.255.0.0 {
    range 192.168.1.10 192.168.2.100;
}
'''), ]

        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)
	failure_dir = {}

	for key in (key for key in g_subscriber_port_map if key != 100):
	    self.host_load(g_subscriber_port_map[key])

	def thread_fun(i, j):
#		log.info("Thread Name:%s",current_thread().name)
#		failure_dir[current_thread().name] = True
	    while failure_dir.has_key(current_thread().name) is False:
		  mac = RandMAC()._fix()
		  cip, sip = DHCPTest(iface = 'veth{}'.format(i)).discover(mac = mac)
		  i += 2
		  log.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
		  self.lock.acquire()

		  if cip:
		     self.ip_count += 1
		     self.lock.notify_all()
		     self.lock.release()
		  elif cip is None:
		     self.failure_count += 1
		     failure_dir[current_thread().name] = True
		     self.lock.notify_all()
		     self.lock.release()
		     break
#		self.lock.notify_all()
#		self.lock.release()

	for i in range (1,4):
	    failure_dir = {}
	    self.ip_count = 0
	    self.failure_count = 0
	    self.start_time = 0
	    self.diff = 0
	    self.transaction_count = 0
	    self.start_time = time.time()

	    while len(failure_dir) != 6:
		  t = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})
		  t1 = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})
		  t2 = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})
		  t3 = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})
		  t4 = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})
		  t5 = threading.Thread(target = thread_fun, kwargs = {'i': 0, 'j': 2})

		  t.start()
		  t1.start()
		  t2.start()
		  t3.start()
		  t4.start()
		  t5.start()

		  t.join()
		  t1.join()
		  t2.join()
		  t3.join()
		  t4.join()
		  t5.join()

		  self.diff = round(time.time() - self.start_time, 0)
	    self.transaction_count = round((self.ip_count)/self.diff, 2)

	    self.transactions += (self.ip_count+self.failure_count)
	    self.running_time += self.diff
	    self.total_success += self.ip_count
	    self.total_failure += self.failure_count


	    log.info("Statistics for run %d",i)
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
	log.info("Average no. of consecutive successful transactions per second: %d", round(self.total_success/self.running_time,2))
	log.info("----------------------------------------------------------------------------------")

    def test_dhcpRelay_concurrent_clients_per_second(self, iface = 'veth0'):

        config = self.default_config
        options = self.default_options
        subnet =  [ ('192.168.1.2',
'''
subnet 192.168.0.0 netmask 255.255.0.0 {
    range 192.168.1.10 192.168.2.100;
}
'''), ]

        dhcpd_interface_list = self.relay_interfaces
        self.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet)

	for key in (key for key in g_subscriber_port_map if key < 100):
		self.host_load(g_subscriber_port_map[key])

	def thread_fun(i):
#		mac = self.get_mac('veth{}'.format(i))
	    cip, sip, mac, _ = DHCPTest(iface = 'veth{}'.format(i)).only_discover(mac = RandMAC()._fix())
	    log.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
	    self.lock.acquire()

	    if cip:
	       self.ip_count += 1
	    elif cip is None:
	       self.failure_count += 1

	    self.lock.notify_all()
	    self.lock.release()

	for i in range (1,4):
	    self.ip_count = 0
	    self.failure_count = 0
	    self.start_time = 0
	    self.diff = 0
	    self.transaction_count = 0
	    self.start_time = time.time()

	    while self.diff <= 60:
		  t = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(0, random.randrange(1,40,1), 1)})
		  t1 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(42, random.randrange(43,80,1), 1)})
		  t2 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(82, random.randrange(83,120,1), 1)})
		  t3 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(122, random.randrange(123,160,1), 1)})
		  t4 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(162, random.randrange(163,180,1), 1)})
		  t5 = threading.Thread(target = thread_fun, kwargs = {'i': random.randrange(182, random.randrange(183,196,1), 1)})

		  t.start()
		  t1.start()
		  t2.start()
		  t3.start()
		  t4.start()
		  t5.start()

		  t.join()
		  t1.join()
		  t2.join()
		  t3.join()
		  t4.join()
		  t5.join()

		  self.diff = round(time.time() - self.start_time, 0)
	    self.transaction_count = round((self.ip_count+self.failure_count)/self.diff, 2)
	    self.transactions += (self.ip_count+self.failure_count)
	    self.running_time += self.diff
	    self.total_success += self.ip_count
	    self.total_failure += self.failure_count

	    log.info("----------------------------------------------------------------------------------")
	    log.info("Statistics for run %d of sending only DHCP Discover",i)
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


    @nottest
    def test_dhcpRelay_inform_packet(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv(mac, inform_packet = True)

    def test_dhcpRelay_client_conflict(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log.info('Got dhcp client IP %s from server %s for mac %s.' %
		  (cip, sip, mac) )
        self.dhcp1 = DHCPTest(seed_ip = cip, iface = iface)
	new_cip, new_sip, new_mac, _ = self.dhcp1.only_discover(desired = True)
	new_cip, new_sip = self.dhcp1.only_request(new_cip, new_mac)
	log.info('Got dhcp client IP %s from server %s for mac %s.' %
		  (new_cip, new_sip, new_mac) )
	log.info("IP %s alredy consumed by mac %s." % (new_cip, new_mac))
	log.info("Now sending DHCP Request for old DHCP discover.")
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	if new_cip is None:
	   log.info('Got dhcp client IP %s from server %s for mac %s.Which is expected behavior.'
                    %(new_cip, new_sip, new_mac) )
	elif new_cip:
	   log.info('Got dhcp client IP %s from server %s for mac %s.Which is not expected behavior as IP %s is already consumed.'
		    %(new_cip, new_sip, new_mac, new_cip) )
	   assert_equal(new_cip, None)



