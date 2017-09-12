
# Copyright 2017-present Open Networking Foundation
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
# WITHOUT WARRANTIES OR CONDITIONS OF AeY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import unittest
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
import time
import os, sys
from DHCP import DHCPTest
from CordTestUtils import get_mac, log_test
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from CordTestServer import cord_test_onos_restart
from CordTestConfig import setup_module, teardown_module
from CordLogger import CordLogger
from portmaps import g_subscriber_port_map
from CordContainer import Onos
from VolthaCtrl import VolthaCtrl
import threading, random
from threading import current_thread
log_test.setLevel('INFO')

class dhcpl2relay_exchange(CordLogger):

    VOLTHA_HOST = None
    VOLTHA_REST_PORT = VolthaCtrl.REST_PORT
    VOLTHA_ENABLED = bool(int(os.getenv('VOLTHA_ENABLED', 0)))
    VOLTHA_OLT_TYPE = 'simulated_olt'
    VOLTHA_OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_UPLINK_VLAN_MAP = { 'of:0000000000000001' : '222' }

    app = 'org.opencord.dhcpl2relay'
    sadis_app = 'org.opencord.sadis'
    app_dhcp = 'org.onosproject.dhcp'
    app_olt = 'org.onosproject.olt'
    relay_interfaces_last = ()
    interface_to_mac_map = {}
    host_ip_map = {}
    test_path = os.path.dirname(os.path.realpath(__file__))
    dhcp_data_dir = os.path.join(test_path, '..', 'setup')
    dhcpl2_app_file = os.path.join(test_path, '..', 'apps/dhcpl2relay-1.0.0.oar')
    olt_app_file = os.path.join(test_path, '..', 'apps/olt-app-1.3.0-SNAPSHOT.oar')
    sadis_app_file = os.path.join(test_path, '..', 'apps/sadis-app-1.0.0-SNAPSHOT.oar')
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config_voltha_local.json'))
    default_config = { 'default-lease-time' : 600, 'max-lease-time' : 7200, }
    default_options = [ ('subnet-mask', '255.255.255.0'),
                     ('broadcast-address', '192.168.1.255'),
                     ('domain-name-servers', '192.168.1.1'),
                     ('domain-name', '"mydomain.cord-tester"'),
                   ]
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
    sadis_configs = {}
    default_onos_netcfg = {}

    @classmethod
    def update_apps_version(cls):
        version = Onos.getVersion()
        major = int(version.split('.')[0])
        minor = int(version.split('.')[1])
        dhcpl2_app_version = '1.0.0'
        sadis_app_version = '1.0.0-SNAPSHOT'
#        sadis-app-1.0.0-SNAPSHOT.oar
#        if major > 1:
#            cordigmp_app_version = '3.0-SNAPSHOT'
#            olt_app_version = '2.0-SNAPSHOT'
#        elif major == 1:
#            if minor > 10:
#                cordigmp_app_version = '3.0-SNAPSHOT'
#                olt_app_version = '2.0-SNAPSHOT'
#            elif minor <= 8:
#                olt_app_version = '1.1-SNAPSHOT'
        cls.dhcpl2_app_file = os.path.join(cls.test_path, '..', 'apps/dhcpl2relay-{}.oar'.format(dhcpl2_app_version))
        cls.sadis_app_file = os.path.join(cls.test_path, '..', 'apps/sadis-app-{}.oar'.format(sadis_app_version))


    @classmethod
    def setUpClass(cls):
        ''' Activate the cord dhcpl2relay app'''
        cls.update_apps_version()
        OnosCtrl(cls.app_dhcp).deactivate()
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.app)
        status, _ = cls.onos_ctrl.activate()
        #assert_equal(status, True)
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.sadis_app)
        status, _ = cls.onos_ctrl.activate()
        #assert_equal(status, True)
        time.sleep(3)
        cls.dhcp_l2_relay_setup()
        cls.cord_sadis_load()
        cls.cord_l2_relay_load()
        ##start dhcpd initially with default config
        #cls.dhcpd_start()

    def setUp(self):
        self.default_onos_netcfg = OnosCtrl.get_config()
        super(dhcpl2relay_exchange, self).setUp()
        self.dhcp_l2_relay_setup()
        self.cord_sadis_load()
        self.cord_l2_relay_load()

    def tearDown(self):
        super(dhcpl2relay_exchange, self).tearDown()
        OnosCtrl.uninstall_app(self.dhcpl2_app_file)
        OnosCtrl.uninstall_app(self.sadis_app_file)
        OnosCtrl.uninstall_app(self.olt_app_file)

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the cord dhcpl2relay app'''
#        OnosCtrl.uninstall_app(cls.dhcpl2_app_file)
#        OnosCtrl.uninstall_app(cls.sadis_app_file)
        cls.onos_ctrl.deactivate()
 #       OnosCtrl(cls.app).deactivate()
        OnosCtrl(cls.sadis_app).deactivate()
        OnosCtrl(cls.app_olt).deactivate()
        #cls.dhcp_l2_relay_cleanup()

    @classmethod
    def dhcp_l2_relay_setup(cls):
        did = OnosCtrl.get_device_ids()
        device_details = OnosCtrl.get_devices()
        if device_details is not None:
           for device in device_details:
             ## Assuming only one OVS is detected on ONOS and its for external DHCP server connect point...
             if device['available'] is True and device['driver'] == 'ovs':
                did_ovs = device['id']
        else:
           log_test.info('On this DHCPl2relay setup, onos does not have ovs device where external DHCP server is have connect point, so return with false status')
           return False
        cls.relay_device_id = did_ovs
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
            #cls.onos_interface_load(interface_list)

    @classmethod
    def dhcp_l2_relay_cleanup(cls):
        ##reset the ONOS port configuration back to default
        for config in cls.configs.items():
            OnosCtrl.delete(config)
        cls.onos_load_config(cls.default_onos_config)
        # if cls.onos_restartable is True:
        #     log_test.info('Cleaning up dhcp relay config by restarting ONOS with default network cfg')
        #     return cord_test_onos_restart(config = {})

    @classmethod
    def onos_load_config(cls, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

    @classmethod
    def onos_delete_config(cls, config):
        status, code = OnosCtrl.delete(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
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
    def cord_l2_relay_load(cls,dhcp_server_connectPoint = None, delete = False):
        OnosCtrl.uninstall_app(cls.dhcpl2_app_file)
        #relay_device_map = '{}/{}'.format(cls.relay_device_id, cls.relay_interface_port)
        #### We have to work on later versions by removing these hard coded values
        relay_device_map = "{}/1".format(cls.relay_device_id)
        relay_device_map3 = "{}/3".format(cls.relay_device_id)
        relay_device_map4 = "{}/4".format(cls.relay_device_id)
        relay_device_map5 = "{}/5".format(cls.relay_device_id)
        relay_device_map6 = "{}/6".format(cls.relay_device_id)
        relay_device_map7 = "{}/7".format(cls.relay_device_id)
        relay_device_map8 = "{}/8".format(cls.relay_device_id)
        relay_device_map9 = "{}/9".format(cls.relay_device_id)
        relay_device_map10 = "{}/10".format(cls.relay_device_id)
        relay_device_map11 = "{}/11".format(cls.relay_device_id)
        relay_device_map12 = "{}/12".format(cls.relay_device_id)
        if dhcp_server_connectPoint is None:
           dhcp_server_connectPoint = [relay_device_map,relay_device_map3,relay_device_map4,relay_device_map5,relay_device_map6,relay_device_map7,relay_device_map8,relay_device_map9,relay_device_map10,relay_device_map11,relay_device_map12]
        print relay_device_map
        dhcp_dict = { "apps" : { "org.opencord.dhcpl2relay" : {"dhcpl2relay" :
                                   {"dhcpserverConnectPoint":dhcp_server_connectPoint}
                                                        }
                            }
                    }
        print "---------------------------------------------"
        print dhcp_dict
        print "---------------------------------------------"
        #OnosCtrl.uninstall_app(cls.dhcpl2_app_file)
        OnosCtrl.install_app(cls.dhcpl2_app_file)
        if delete == False:
           cls.onos_load_config(dhcp_dict)
        else:
           cls.onos_delete_config(dhcp_dict)
           cls.onos_load_config(cls.default_onos_config)
        cls.configs['relay_config'] = dhcp_dict

    @classmethod
    def cord_sadis_load(cls, sadis_info = None):
        relay_device_id = '{}'.format(cls.relay_device_id)
        device_details = OnosCtrl.get_devices()
        if device_details is not None:
           for device in device_details:
             ## Assuming only one OVS is detected on ONOS and its for external DHCP server connect point...
             if device['available'] is True and device['driver'] == 'pmc-olt':
                cls.olt_serial_id = "{}".format(device['serial'])
             else:
                cls.olt_serial_id = " "
        else:
           log_test.info('On this DHCPl2relay setup, onos does not have Tibit device where DHCP client is connected on UNI point, so return with false status')
           return False
        sadis_dict =  { "apps": {
                "org.opencord.sadis": {
                        "sadis": {
                                "integration": {
                                        "cache": {
                                                "enabled": "true",
                                                "maxsize": 50,
                                                "ttl": "PT1m"
                                        }
                                },
                                "entries": [{
                                                "id": "uni-254",
                                                "cTag": 202,
                                                "sTag": 222,
                                                "nasPortId": "uni-254"
                                        },
                                        {
                                                "id": cls.olt_serial_id,
                                                "hardwareIdentifier": "00:0c:e2:31:05:00",
                                                "ipAddress": "172.17.0.1",
                                                "nasId": "B100-NASID"
                                        }
                                ]
                        }
                }
           }
        }
        #OnosCtrl.uninstall_app(cls.olt_app_file)
        OnosCtrl.install_app(cls.olt_app_file)
        time.sleep(5)
        #OnosCtrl.uninstall_app(cls.sadis_app_file)
        OnosCtrl.install_app(cls.sadis_app_file)
        if sadis_info:
           sadis_dict = sadis_info
        cls.onos_load_config(sadis_dict)
        cls.sadis_configs['relay_config'] = sadis_dict

    def sadis_info_dict(self, subscriber_port_id =None, c_tag = None, s_tag = None, nas_port_id =None,olt_serial_id =None,olt_mac=None,olt_ip =None,olt_nas_id=None):
        ### Need to work on these hard coded values on later merges
        if subscriber_port_id is None:
           subscriber_port_id = "uni-254"
        if c_tag is None:
           c_tag = 202
        if s_tag is None:
           s_tag = 222
        if nas_port_id is None:
           nas_port_id = "uni-254"
        if olt_serial_id is None:
           olt_serial_id = self.olt_serial_id
        if olt_mac is None:
           olt_mac = "00:0c:e2:31:05:00"
        if olt_ip is None:
           olt_ip = "172.17.0.1"
        if olt_nas_id is None:
           olt_nas_id = "B100-NASID"
        sadis_dict =  { "apps": {
                "org.opencord.sadis": {
                        "sadis": {
                                "integration": {
                                        "cache": {
                                                "enabled": "true",
                                                "maxsize": 50,
                                                "ttl": "PT1m"
                                        }
                                },
                                "entries": [{
                                                "id": subscriber_port_id,
                                                "cTag": c_tag,
                                                "sTag": s_tag,
                                                "nasPortId": nas_port_id
                                        },
                                        {
                                                "id": olt_serial_id,
                                                "hardwareIdentifier": olt_mac,
                                                "ipAddress": olt_ip,
                                                "nasId": olt_nas_id
                                        }
                                ]
                        }
                }
           }
        }
        return sadis_dict


    @classmethod
    def get_host_ip(cls, port):
        if cls.host_ip_map.has_key(port):
            return cls.host_ip_map[port]
        cls.host_ip_map[port] = '192.168.100.{}'.format(port)
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
    def get_mac(cls, iface):
        if cls.interface_to_mac_map.has_key(iface):
            return cls.interface_to_mac_map[iface]
        mac = get_mac(iface, pad = 0)
        cls.interface_to_mac_map[iface] = mac
        return mac

    def dhcpl2relay_stats_calc(self, success_rate = False, only_discover = False, iface = 'veth0'):

	self.ip_count = 0
	self.failure_count = 0
	self.start_time = 0
	self.diff = 0
	self.transaction_count = 0

        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
	self.start_time = time.time()

	while self.diff <= 60:

	    if only_discover:
		cip, sip, mac, _ = self.dhcp.only_discover(multiple = True)
                log_test.info('Got dhcp client IP %s from server %s for mac %s' %
                        (cip, sip, mac))
	    else:
	        cip, sip = self.send_recv(mac=mac, update_seed = True, validate = False)

	    if cip:
                self.ip_count +=1
	    elif cip == None:
		self.failure_count += 1
                log_test.info('Failed to get ip')
		if success_rate and self.ip_count > 0:
			break

	    self.diff = round(time.time() - self.start_time, 0)

	self.transaction_count = round((self.ip_count+self.failure_count)/self.diff, 2)
        self.transactions += (self.ip_count+self.failure_count)
	self.running_time += self.diff
        self.total_success += self.ip_count
	self.total_failure += self.failure_count

    def send_recv(self, mac=None, update_seed = False, validate = True):
        cip, sip = self.dhcp.discover(mac = mac, update_seed = update_seed)
        if validate:
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
        log_test.info('Got dhcp client IP %s from server %s for mac %s' %
                (cip, sip, self.dhcp.get_mac(cip)[0]))
        return cip,sip

    def test_dhcpl2relay_with_one_request(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv(mac=mac)

    def test_dhcpl2relay_app_install(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.dhcpl2relay'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               app_status = True
        if app_status is not True:
           log_test.info('%s app is not being installed'%app_name)
           assert_equal(True, app_status)

    def test_dhcpl2relay_sadis_app_install(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               app_status = True
        if app_status is not True:
           log_test.info('%s app is not being installed'%app_name)
           assert_equal(True, app_status)

    def test_dhcpl2relay_netcfg(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.dhcpl2relay'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               else:
                  log_test.info('The network configuration is shown = %s'%onos_netcfg['apps'][app_name])
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown'%app_name)
           assert_equal(True, False)

    def test_dhcpl2relay_sadis_netcfg(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               else:
                  log_test.info('The network configuration is shown = %s'%(onos_netcfg['apps'][app_name]))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown'%app_name)
           assert_equal(True, False)

    def test_dhcpl2relay_with_array_of_connect_points_for_dhcp_server(self, iface = 'veth0'):
        relay_device_map = '{}/{}'.format(self.relay_device_id, self.relay_interface_port)
        relay_device_map1 = '{}/1'.format(self.relay_device_id)
        relay_device_map2 = '{}/9'.format(self.relay_device_id)
        relay_device_map3 = '{}/6'.format(self.relay_device_id)
        relay_device_map4 = '{}/7'.format(self.relay_device_id)
        dhcp_server_array_connectPoints = [relay_device_map,relay_device_map1,relay_device_map2,relay_device_map3,relay_device_map4]
        mac = self.get_mac(iface)
        self.onos_delete_config(self.configs['relay_config'])
        self.onos_load_config(self.default_onos_netcfg)
        self.cord_l2_relay_load(dhcp_server_connectPoint = dhcp_server_array_connectPoints, delete = False)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.dhcpl2relay'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['dhcpServerConnectPoints'] == dhcp_server_array_connectPoints:
                  log_test.info('The network configuration is shown = %s'%onos_netcfg['apps'][app_name]['dhcpServerConnectPoints'])
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown'%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv(mac=mac)


    def test_dhcpl2relay_with_subscriber_configured_with_ctag_stag_as_per_sadis(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        c_tag = 600
        invalid_sadis_info = self.sadis_info_dict(c_tag = 600,s_tag = 500)
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['cTag'] == c_tag:
                  log_test.info('The S Tag and C Tag info from network configuration are %s and %s respectively '%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['sTag'],onos_netcfg['apps'][app_name]['sadis']['entries'][0]['cTag']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_app_activation_and_deactivation_multiple_times(self, iface = 'veth0'):
        iterations = 15
        for i in range(iterations):
            self.onos_ctrl.deactivate()
            time.sleep(3)
            self.onos_ctrl.activate()
        log_test.info('Dhcpl2relay app is activated and deactivated multiple times around %s, now sending DHCP discover'%iterations)
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        self.send_recv(mac=mac)

    def test_dhcpl2relay_without_sadis_app(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        OnosCtrl.uninstall_app(self.sadis_app_file)
        OnosCtrl(self.sadis_app).deactivate()
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_delete_and_add_sadis_app(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        OnosCtrl.uninstall_app(self.sadis_app_file)
        OnosCtrl(self.sadis_app).deactivate()
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)
        OnosCtrl.uninstall_app(self.sadis_app_file)
        OnosCtrl(self.sadis_app).deactivate()
        #self.onos_load_config(self.sadis_configs['relay_config'])
        self.send_recv(mac=mac)

    def test_dhcpl2relay_with_option_82(self, iface = 'veth0'):
        pass

    def test_dhcpl2relay_without_option_82(self, iface = 'veth0'):
        pass

    def test_dhcl2relay_for_option82_without_configuring_dhcpserver_to_accept_option82(self, iface = 'veth0'):
        pass

    def test_dhcpl2relay_with_different_uni_port_entry_sadis_config(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        subscriber_port_id = "uni-200"
        invalid_sadis_info = self.sadis_info_dict(subscriber_port_id = "uni-200")
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['id'] == subscriber_port_id:
                  log_test.info('The network configuration is shown = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['id']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)

           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_with_different_ctag_options(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        c_tag = 600
        invalid_sadis_info = self.sadis_info_dict(c_tag = 600)
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['cTag'] == c_tag:
                  log_test.info('The C Tag info from network configuration is = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['cTag']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_with_different_stag_options(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        s_tag = 600
        invalid_sadis_info = self.sadis_info_dict(s_tag = 600)
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['sTag'] == s_tag:
                  log_test.info('The S Tag info from the network configuration is = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['sTag']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_without_nasportid_option_in_sadis(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        invalid_sadis_info = self.sadis_info_dict(nas_port_id = " ")
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['nasPortId'] == " ":
                  log_test.info('The nasPortId info from network configuration is shown = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['nasPortId']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_with_nasportid_different_from_id(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        nas_port_id = "uni-509"
        invalid_sadis_info = self.sadis_info_dict(nas_port_id = "uni-509")
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][0]['nasPortId'] == nas_port_id:
                  log_test.info('The nasPortId info from network configuration is shown = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][0]['nasPortId']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_without_serial_id_of_olt(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        invalid_sadis_info = self.sadis_info_dict(olt_serial_id = " ")
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][1]['id'] == " ":
                  log_test.info('The serial Id info from network configuration is shown = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][1]['id']))
                  app_status = True
        if app_status is not True:
           log_test.info('%s app is not installed or network configuration is not shown '%app_name)
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_with_wrong_serial_id_of_olt(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        olt_serial_id = "07f20d06696041febf974ccdhdhhjh37"
        invalid_sadis_info = self.sadis_info_dict(olt_serial_id = "07f20d06696041febf974ccdhdhhjh37")
        self.cord_sadis_load(sadis_info = invalid_sadis_info)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.sadis'
        for app in onos_netcfg['apps']:
            if app == app_name:
               log_test.info('%s app is being installed'%app)
               if onos_netcfg['apps'][app_name] == {}:
                  log_test.info('The network configuration is not shown'%onos_netcfg['apps'][app_name])
               elif onos_netcfg['apps'][app_name]['sadis']['entries'][1]['id'] == olt_serial_id:
                  log_test.info('The serial Id info from network configuration is shown = %s'%(onos_netcfg['apps'][app_name]['sadis']['entries'][1]['id']))
                  app_status = True
        if app_status is not True:
           assert_equal(True, False)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)

    def test_dhcpl2relay_for_one_request_with_invalid_source_mac_broadcast(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac='ff:ff:ff:ff:ff:ff')
        assert_equal(cip,None)
	log_test.info('Dhcp server rejected client discover with invalid source mac, as expected')

    def test_dhcpl2relay_for_one_request_with_invalid_source_mac_multicast(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac='01:80:c2:01:98:05')
        assert_equal(cip,None)
	log_test.info('Dhcp server rejected client discover with invalid source mac, as expected')

    def test_dhcpl2relay_for_one_request_with_invalid_source_mac_zero(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac='00:00:00:00:00:00')
        assert_equal(cip,None)
        log_test.info('dhcp server rejected client discover with invalid source mac, as expected')

    def test_dhcpl2relay_with_N_requests(self, iface = 'veth0',requests=10):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '192.169.100.1', iface = iface)
        ip_map = {}
        for i in range(requests):
            #mac = RandMAC()._fix()
	    #log_test.info('mac is %s'%mac)
            cip, sip = self.send_recv(update_seed = True)
            if ip_map.has_key(cip):
                log_test.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip
	    time.sleep(1)

    def test_dhcpl2relay_with_one_release(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcp.release(cip), True)
        log_test.info('Triggering DHCP discover again after release')
        cip2, sip2 = self.send_recv(mac=mac)
        log_test.info('Verifying released IP was given back on rediscover')
        assert_equal(cip, cip2)
        log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
        assert_equal(self.dhcp.release(cip2), True)

    def test_dhcpl2relay_with_Nreleases(self, iface = 'veth0'):
        mac = None
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = iface)
        ip_map = {}
        for i in range(10):
            cip, sip = self.send_recv(mac=mac, update_seed = True)
            if ip_map.has_key(cip):
                log_test.info('IP %s given out multiple times' %cip)
                assert_equal(False, ip_map.has_key(cip))
            ip_map[cip] = sip

        for ip in ip_map.keys():
            log_test.info('Releasing IP %s' %ip)
            assert_equal(self.dhcp.release(ip), True)

        ip_map2 = {}
        log_test.info('Triggering DHCP discover again after release')
        self.dhcp = DHCPTest(seed_ip = '192.170.1.10', iface = iface)
        for i in range(len(ip_map.keys())):
            cip, sip = self.send_recv(mac=mac, update_seed = True)
            ip_map2[cip] = sip

        log_test.info('Verifying released IPs were given back on rediscover')
        if ip_map != ip_map2:
            log_test.info('Map before release %s' %ip_map)
            log_test.info('Map after release %s' %ip_map2)
        assert_equal(ip_map, ip_map2)

    def test_dhcpl2relay_starvation(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
        log_test.info('Verifying 1 ')
	count = 0
        while True:
            #mac = RandMAC()._fix()
            cip, sip = self.send_recv(update_seed = True,validate = False)
	    if cip is None:
		break
	    else:
		count += 1
	assert_equal(count,91)
        log_test.info('Verifying 2 ')
        cip, sip = self.send_recv(mac=mac, update_seed = True, validate = False)
        assert_equal(cip, None)
        assert_equal(sip, None)

    def test_dhcpl2relay_with_same_client_and_multiple_discovers(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	log_test.info('Triggering DHCP discover again.')
	new_cip, new_sip, new_mac, _ = self.dhcp.only_discover()
	assert_equal(new_cip, cip)
	log_test.info('got same ip to smae the client when sent discover again, as expected')

    def test_dhcpl2relay_with_same_client_and_multiple_requests(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	log_test.info('Sending DHCP discover and DHCP request.')
	cip, sip = self.send_recv(mac=mac)
	mac = self.dhcp.get_mac(cip)[0]
	log_test.info("Sending DHCP request again.")
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info('got same ip to smae the client when sent request again, as expected')

    def test_dhcpl2relay_with_clients_desired_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '192.168.1.31', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
	assert_equal(cip,self.dhcp.seed_ip)
	log_test.info('Got dhcp client desired IP %s from server %s for mac %s as expected' %
		  (cip, sip, mac) )

    def test_dhcpl2relay_with_clients_desired_address_in_out_of_pool(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.35', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(desired = True)
	assert_not_equal(cip,None)
	assert_not_equal(cip,self.dhcp.seed_ip)
	log_test.info('server offered IP from its pool when requested out of pool IP, as expected')

    def test_dhcpl2relay_nak_packet(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request('20.20.20.31', mac)
	assert_equal(new_cip, None)
	log_test.info('server sent NAK packet when requested other IP than that server offered')

    def test_dhcpl2relay_with_client_requests_with_specific_lease_time_in_discover_message(self, iface = 'veth0',lease_time=700):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.70', iface = iface)
	self.dhcp.return_option = 'lease'
	cip, sip, mac, lval = self.dhcp.only_discover(lease_time=True,lease_value=lease_time)
	assert_equal(lval, lease_time)
	log_test.info('dhcp server offered IP address with client requested lease time')

    def test_dhcpl2relay_with_client_request_after_reboot(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	log_test.info('client rebooting...')
	os.system('ifconfig '+iface+' down')
	time.sleep(5)
	os.system('ifconfig '+iface+' up')
	new_cip2, new_sip = self.dhcp.only_request(cip, mac, cl_reboot = True)
	assert_equal(new_cip2, cip)
	log_test.info('client got same IP after reboot, as expected')


    def test_dhcpl2relay_after_server_reboot(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	log_test.info('server rebooting...')
	self.tearDownClass()
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip,None)
	self.setUpClass()
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info('client got same IP after server rebooted, as expected')

    def test_dhcpl2relay_specific_lease_time_only_in_discover_but_not_in_request_packet(self, iface = 'veth0',lease_time=700):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	self.dhcp.return_option = 'lease'
	log_test.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, lval = self.dhcp.only_discover(lease_time = True, lease_value=lease_time)
	assert_equal(lval,lease_time)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True)
	assert_equal(new_cip,cip)
	assert_not_equal(lval, lease_time) #Negative Test Case
	log_test.info('client requested lease time in discover packer is not seen in server ACK packet as expected')

    def test_dhcpl2relay_specific_lease_time_only_in_request_but_not_in_discover_packet(self, iface = 'veth0',lease_time=800):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True,lease_value=lease_time)
	assert_equal(new_cip,cip)
	assert_equal(lval, lease_time)
	log_test.info('client requested lease time in request packet seen in servre replied ACK packet as expected')

    def test_dhcpl2relay_with_client_renew_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
	log_test.info('waiting for  renew  time..')
	time.sleep(lval)
	latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac, unicast = True)
	assert_equal(latest_cip, cip)
	log_test.info('server renewed client IP when client sends request after renew time, as expected')

    def test_dhcpl2relay_with_client_rebind_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, rebind_time = True)
	log_test.info('waiting for  rebind  time..')
	time.sleep(lval)
	latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac)
	assert_equal(latest_cip, cip)
        log_test.info('server renewed client IP when client sends request after rebind time, as expected')

    def test_dhcpl2relay_with_client_expected_subnet_mask(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_subnet = '255.255.255.0'
	self.dhcp.return_option = 'subnet'

	cip, sip, mac, subnet_mask = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(subnet_mask,expected_subnet)
	log_test.info('subnet mask in server offer packet is same as configured subnet mask in dhcp server')

    def test_dhcpl2relay_with_client_sending_dhcp_request_with_wrong_subnet_mask(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	self.dhcp.send_different_option = 'subnet'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info("Got DHCP Ack despite of specifying wrong Subnet Mask in DHCP Request.")

    def test_dhcpl2relay_with_client_expected_router_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_router_address = '20.20.20.1'
	self.dhcp.return_option = 'router'

	cip, sip, mac, router_address_value = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_router_address, router_address_value)
	log_test.info('router address in server offer packet is same as configured router address in dhcp server')

    def test_dhcpl2relay_with_client_sends_dhcp_request_with_wrong_router_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	self.dhcp.send_different_option = 'router'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info("Got DHCP Ack despite of specifying wrong Router Address in DHCP Request.")

    def test_dhcpl2relay_with_client_expecting_broadcast_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_broadcast_address = '192.168.1.255'
	self.dhcp.return_option = 'broadcast_address'

	cip, sip, mac, broadcast_address_value = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_broadcast_address, broadcast_address_value)
	log_test.info('broadcast address in server offer packet is same as configured broadcast address in dhcp server')

    def test_dhcpl2relay_with_client_sends_dhcp_request_with_wrong_broadcast_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	self.dhcp.send_different_option = 'broadcast_address'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info("Got DHCP Ack despite of specifying wrong Broadcast Address in DHCP Request.")

    def test_dhcpl2relay_with_client_expecting_dns_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_dns_address = '192.168.1.1'
	self.dhcp.return_option = 'dns'

	cip, sip, mac, dns_address_value = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_dns_address, dns_address_value)
	log_test.info('dns address in server offer packet is same as configured dns address in dhcp server')

    def test_dhcpl2relay_with_client_sends_request_with_wrong_dns_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	self.dhcp.send_different_option = 'dns'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info("Got DHCP Ack despite of specifying wrong DNS Address in DHCP Request.")


    def test_dhcpl2relay_transactions_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.dhcpl2relay_stats_calc()
	    log_test.info("Statistics for run %d",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	    log_test.info("    %d                    %d                     %d                  %d" %(self.ip_count+self.failure_count, 		               self.ip_count, self.failure_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions per second in run %d:%f" %(i, self.transaction_count))

	log_test.info("Final Statistics for total transactions")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log_test.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of transactions per second: %d", round(self.transactions/self.running_time,0))

    def test_dhcpl2relay_consecutive_successes_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.dhcpl2relay_stats_calc(success_rate = True)
	    log_test.info("Statistics for run %d",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of consecutive successful transactions          Running Time ")
	    log_test.info("                   %d                                   %d        " %(self.ip_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of successful transactions per second in run %d:%f" %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")

	log_test.info("Final Statistics for total successful transactions")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of consecutive successes         Running Time ")
	log_test.info("    %d                                 %d                             %d        " %(self.transactions,
                 self.total_success, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of consecutive successful transactions per second: %d", round(self.total_success/self.running_time,0))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_with_max_clients_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.dhcpl2relay_stats_calc(only_discover = True)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("Statistics for run %d of sending only DHCP Discover",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	    log_test.info("    %d                    %d                     %d                  %d" %(self.ip_count+self.failure_count, 		               self.ip_count, self.failure_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of clients per second in run %d:%f                                      "
		    %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Final Statistics for total transactions of sending only DHCP Discover")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log_test.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of clients per second: %d                                        ",
		round(self.transactions/self.running_time,0))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_consecutive_successful_clients_per_second(self, iface = 'veth0'):

	for i in range(1,4):
	    self.dhcpl2relay_stats_calc(success_rate = True, only_discover = True)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("Statistics for run %d for sending only DHCP Discover",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of consecutive successful transactions          Running Time ")
	    log_test.info("                   %d                                   %d        " %(self.ip_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of consecutive successful clients per second in run %d:%f" %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")

	log_test.info("Final Statistics for total successful transactions")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of consecutive successes         Running Time ")
	log_test.info("    %d                                 %d                             %d        " %(self.transactions,
                 self.total_success, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of consecutive successful clients per second: %d", round(self.total_success/self.running_time,0))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_concurrent_transactions_per_second(self, iface = 'veth0'):
	for key in (key for key in g_subscriber_port_map if key < 100):
	    self.host_load(g_subscriber_port_map[key])

	def thread_fun(i):
	    mac = self.get_mac('veth{}'.format(i))
	    cip, sip = DHCPTest(iface = 'veth{}'.format(i)).discover(mac = mac)
	    log_test.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
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


	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("Statistics for run %d",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	    log_test.info("    %d                    %d                     %d                  %d"
			    %(self.ip_count+self.failure_count,self.ip_count, self.failure_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions per second in run %d:%f" %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")

	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Final Statistics for total transactions")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log_test.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))

	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of transactions per second: %d", round(self.transactions/self.running_time,0))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_concurrent_consecutive_successes_per_second(self, iface = 'veth0'):
	failure_dir = {}

	for key in (key for key in g_subscriber_port_map if key != 100):
	    self.host_load(g_subscriber_port_map[key])

	def thread_fun(i, j):
#		log_test.info("Thread Name:%s",current_thread().name)
#		failure_dir[current_thread().name] = True
	    while failure_dir.has_key(current_thread().name) is False:
		  mac = RandMAC()._fix()
		  cip, sip = DHCPTest(iface = 'veth{}'.format(i)).discover(mac = mac)
		  i += 2
		  log_test.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
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


	    log_test.info("Statistics for run %d",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of consecutive successful transactions          Running Time ")
	    log_test.info("                   %d                                   %d        " %(self.ip_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of successful transactions per second in run %d:%f" %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")

	log_test.info("Final Statistics for total successful transactions")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of consecutive successes         Running Time ")
	log_test.info("    %d                                 %d                             %d        " %(self.transactions,
                 self.total_success, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of consecutive successful transactions per second: %d", round(self.total_success/self.running_time,2))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_for_concurrent_clients_per_second(self, iface = 'veth0'):
	for key in (key for key in g_subscriber_port_map if key < 100):
		self.host_load(g_subscriber_port_map[key])

	def thread_fun(i):
#		mac = self.get_mac('veth{}'.format(i))
	    cip, sip, mac, _ = DHCPTest(iface = 'veth{}'.format(i)).only_discover(mac = RandMAC()._fix())
	    log_test.info('Got dhcp client IP %s from server %s for mac %s'%(cip, sip, mac))
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

	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("Statistics for run %d of sending only DHCP Discover",i)
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of transactions     No. of successes     No. of failures     Running Time ")
	    log_test.info("    %d                    %d                     %d                  %d" %(self.ip_count+self.failure_count, 		               self.ip_count, self.failure_count, self.diff))
	    log_test.info("----------------------------------------------------------------------------------")
	    log_test.info("No. of clients per second in run %d:%f                                      "
		    %(i, self.transaction_count))
	    log_test.info("----------------------------------------------------------------------------------")

	log_test.info("Final Statistics for total transactions of sending only DHCP Discover")
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Total transactions     Total No. of successes     Total No. of failures     Running Time ")
	log_test.info("    %d                     %d                         %d                        %d" %(self.transactions,
                 self.total_success, self.total_failure, self.running_time))
	log_test.info("----------------------------------------------------------------------------------")
	log_test.info("Average no. of clients per second: %d                                        ",
		round(self.transactions/self.running_time,0))
	log_test.info("----------------------------------------------------------------------------------")

    def test_dhcpl2relay_with_client_conflict(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.host_load(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover()
	log_test.info('Got dhcp client IP %s from server %s for mac %s.' %
		  (cip, sip, mac) )
        self.dhcp1 = DHCPTest(seed_ip = cip, iface = iface)
	new_cip, new_sip, new_mac, _ = self.dhcp1.only_discover(desired = True)
	new_cip, new_sip = self.dhcp1.only_request(new_cip, new_mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s.' %
		  (new_cip, new_sip, new_mac) )
	log_test.info("IP %s alredy consumed by mac %s." % (new_cip, new_mac))
	log_test.info("Now sending DHCP Request for old DHCP discover.")
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	if new_cip is None:
	   log_test.info('Got dhcp client IP %s from server %s for mac %s.Which is expected behavior.'
                    %(new_cip, new_sip, new_mac) )
	elif new_cip:
	   log_test.info('Got dhcp client IP %s from server %s for mac %s.Which is not expected behavior as IP %s is already consumed.'
		    %(new_cip, new_sip, new_mac, new_cip) )
	   assert_equal(new_cip, None)
