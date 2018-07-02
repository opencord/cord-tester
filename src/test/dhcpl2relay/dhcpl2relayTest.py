
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
import os, sys, re, json
from DHCP import DHCPTest
from CordTestUtils import get_mac, log_test, getstatusoutput, get_controller
from SSHTestAgent import SSHTestAgent
from OnosCtrl import OnosCtrl
from onosclidriver import OnosCliDriver
from OltConfig import OltConfig
from CordTestServer import cord_test_onos_restart, cord_test_ovs_flow_add,cord_test_onos_shutdown
from CordTestConfig import setup_module, teardown_module
from CordLogger import CordLogger
from portmaps import g_subscriber_port_map
from CordContainer import Onos
from VolthaCtrl import VolthaCtrl
import threading, random
from threading import current_thread
import requests
log_test.setLevel('INFO')

class dhcpl2relay_exchange(CordLogger):

    VOLTHA_HOST = None
    VOLTHA_REST_PORT = VolthaCtrl.REST_PORT
    VOLTHA_ENABLED = bool(int(os.getenv('VOLTHA_ENABLED', 0)))
    VOLTHA_OLT_TYPE = 'simulated_olt'
    VOLTHA_OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_UPLINK_VLAN_MAP = { 'of:0000000000000001' : '222' }
    TAGGED_TRAFFIC = False
    app = 'org.opencord.dhcpl2relay'
    sadis_app = 'org.opencord.sadis'
    app_dhcp = 'org.onosproject.dhcp'
    app_olt = 'org.onosproject.olt'
    relay_interfaces = ()
    relay_interfaces_last = ()
    interface_to_mac_map = {}
    relay_vlan_map = {}
    host_ip_map = {}
    test_path = os.path.dirname(os.path.realpath(__file__))
    dhcp_data_dir = os.path.join(test_path, '..', 'setup')
    dhcpl2_app_file = os.path.join(test_path, '..', 'apps/dhcpl2relay-1.0.0.oar')
    olt_app_file = os.path.join(test_path, '..', 'apps/olt-app-3.0-SNAPSHOT.oar')
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
    voltha_switch_map = None
    remote_dhcpd_cmd = []
    ONOS_INSTANCES = 3
    relay_device_id = None

    @classmethod
    def update_apps_version(cls):
        version = Onos.getVersion()
        major = int(version.split('.')[0])
        minor = int(version.split('.')[1])
        dhcpl2_app_version = '1.0.0'
        sadis_app_version = '3.0-SNAPSHOT'
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
        status, _ = OnosCtrl(cls.sadis_app).activate()
        #assert_equal(status, True)
        time.sleep(3)
        cls.setup_dhcpd()
        cls.default_onos_netcfg = OnosCtrl.get_config()


    def setUp(self):
        super(dhcpl2relay_exchange, self).setUp()
        #self.dhcp_l2_relay_setup()
        #self.cord_sadis_load()
        #self.cord_l2_relay_load()

    def tearDown(self):
        super(dhcpl2relay_exchange, self).tearDown()
        #OnosCtrl.uninstall_app(self.dhcpl2_app_file)
        #OnosCtrl.uninstall_app(self.sadis_app_file)
        #OnosCtrl.uninstall_app(self.olt_app_file)

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the cord dhcpl2relay app'''
        cls.onos_load_config(cls.default_onos_netcfg)
        #cls.onos_ctrl.deactivate()
        #OnosCtrl(cls.sadis_app).deactivate()
        #OnosCtrl(cls.app_olt).deactivate()

    @classmethod
    def setup_dhcpd(cls, boot_delay = 5):
        device_details = OnosCtrl.get_devices(mfr = 'Nicira')
           ## Assuming only one OVS is detected on ONOS and its for external DHCP server connect point...
        if device_details is not None:
           did_ovs = device_details[0]['id']
        else:
           log_test.info('On this DHCPl2relay setup, onos does not have ovs device where external DHCP server is have connect point, so return with false status')
           return False
        cls.relay_device_id = did_ovs
        device_details = OnosCtrl.get_devices()
        if device_details is not None:
           for device in device_details:
               if device['available'] is True and device['driver'] == 'voltha':
                  cls.olt_serial_id = "{}".format(device['serial'])
                  break
               else:
                  cls.olt_serial_id = " "
        else:
            log_test.info('On this DHCPl2relay setup, onos does not have ovs device where external DHCP server is have connect point, so return with false status')
            return False
        if cls.service_running("/usr/sbin/dhcpd"):
            print('DHCPD already running in container')
            return True
        setup_for_relay = cls.dhcp_l2_relay_setup()
        cls.cord_l2_relay_load()
        cls.voltha_setup()
        return True

        # dhcp_start_status = cls.dhcpd_start()
        # if setup_for_relay and dhcp_start_status:
        #     return True
        # return False

    @classmethod
    def config_olt(cls, switch_map):
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
                requests.post(rest_url, auth = auth)

    @classmethod
    def voltha_setup(cls):
        s_tag_map = {}
        #configure olt app to provision dhcp flows
        cls.config_olt(cls.voltha_switch_map)
        for switch, switch_map in cls.voltha_switch_map.iteritems():
            s_tag_map[int(switch_map['uplink_vlan'])] = map(lambda p: int(p), switch_map['ports'])

        cmd_list = []
        relay_interface = cls.relay_interfaces[0]
        cls.relay_vlan_map[relay_interface] = []
        for s_tag, ports in s_tag_map.iteritems():
            vlan_stag_intf = '{}.{}'.format(relay_interface, s_tag)
            cmd = 'ip link add link %s name %s type vlan id %d' %(relay_interface, vlan_stag_intf, s_tag)
            cmd_list.append(cmd)
            cmd = 'ip link set %s up' %(vlan_stag_intf)
            cmd_list.append(cmd)
            for port in ports:
                vlan_ctag_intf = '{}.{}.{}'.format(relay_interface, s_tag, port)
                cmd = 'ip link add link %s name %s type vlan id %d' %(vlan_stag_intf, vlan_ctag_intf, port)
                cmd_list.append(cmd)
                cmd = 'ip link set %s up' %(vlan_ctag_intf)
                cmd_list.append(cmd)
                cls.relay_vlan_map[relay_interface].append(vlan_ctag_intf)
            cls.relay_vlan_map[relay_interface].append(vlan_stag_intf)

        for cmd in cmd_list:
            log_test.info('Running command: %s' %cmd)
            os.system(cmd)

        cord_test_ovs_flow_add(cls.relay_interface_port)
        for s_tag in s_tag_map.keys():
            log_test.info('Configuring OVS flow for port %d, s_tag %d' %(cls.relay_interface_port, s_tag))
            cord_test_ovs_flow_add(cls.relay_interface_port, s_tag)

    @classmethod
    def service_running(cls, pattern):
        st, output = getstatusoutput('pgrep -f "{}"'.format(pattern))
        return True if st == 0 else False

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
        intf_list = list(intf_list)
        ##stop dhcpd if already running
        #cls.dhcpd_stop()
        dhcp_conf = cls.dhcpd_conf_generate(config = config, options = options,
                                            subnet = subnet)
        ##first touch dhcpd.leases if it doesn't exist
        lease_file = '{}/dhcpd.leases'.format(cls.dhcp_data_dir)
        if os.access(lease_file, os.F_OK) is False:
            with open(lease_file, 'w') as fd: pass

        lease_file_tagged = '{}/dhcpd-tagged.leases'.format(cls.dhcp_data_dir)
        if os.access(lease_file_tagged, os.F_OK) is False:
            with open(lease_file_tagged, 'w') as fd: pass

        conf_file = '{}/dhcpd.conf'.format(cls.dhcp_data_dir)
        with open(conf_file, 'w') as fd:
            fd.write(dhcp_conf)

        conf_file_tagged = '{}/dhcpd-tagged.conf'.format(cls.dhcp_data_dir)
        with open(conf_file_tagged, 'w') as fd:
            fd.write(dhcp_conf)

        #now configure the dhcpd interfaces for various subnets
        index = 0
        intf_info = []
        vlan_intf_list = []
        for ip,_ in subnet:
            vlan_intf = None
            intf = intf_list[index]
            if intf in cls.relay_vlan_map:
                vlan_intf = cls.relay_vlan_map[intf][0]
                vlan_intf_list.append(vlan_intf)
            mac = cls.get_mac(intf)
            intf_info.append((ip, mac))
            index += 1
            cmd = 'ifconfig {} {}'.format(intf, ip)
            status = os.system(cmd)
            if vlan_intf:
                cmd = 'ifconfig {} {}'.format(vlan_intf, ip)
                os.system(cmd)

        intf_str = ','.join(intf_list)
        dhcpd_cmd = '/usr/sbin/dhcpd -4 --no-pid -cf {0} -lf {1} {2}'.format('/root/test/src/test/setup/dhcpd.conf','/root/test/src/test/setup/dhcpd.leases', intf_str)
        print('Starting DHCPD server with command: %s' %dhcpd_cmd)
        status = os.system(dhcpd_cmd)
        vlan_intf_str = ','.join(vlan_intf_list)
        dhcpd_cmd = '/usr/sbin/dhcpd -4 --no-pid -cf {0} -lf {1} {2}'.format('/root/test/src/test/setup/dhcpd-tagged.conf','/root/test/src/test/setup/dhcpd-tagged.leases', vlan_intf_str)
        print('Starting DHCPD server with command: %s' %dhcpd_cmd)
        status = os.system(dhcpd_cmd)
        if status > 255:
           status = 1
        else:
           return False
        time.sleep(3)
        cls.relay_interfaces_last = cls.relay_interfaces
        cls.relay_interfaces = intf_list
        return True

    @classmethod
    def get_dhcpd_process(cls):
        docker_cmd = 'docker exec cord-tester1'
        cmd = '{} ps -eaf | grep dhcpd'.format(docker_cmd)
        dhcpd_server_ip = get_controller()
        server_user = 'ubuntu'
        server_pass = 'ubuntu'
        ssh_agent = SSHTestAgent(host = dhcpd_server_ip, user = server_user, password = server_user)
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        if output:
           cls.remote_dhcpd_cmd = re.findall('(?<=/)\w+.*', output)
        log_test.info('DHCP server running on remote host and list of service commands are \n %s'%cls.remote_dhcpd_cmd)
        assert_equal(status, True)
        return cls.remote_dhcpd_cmd

    def dhcpd_stop(self, remote_controller = False, dhcpd = None):
        if remote_controller is not True:
           if cls.service_running("/usr/sbin/dhcpd"):
              cmd = 'pkill -9 dhcpd'
              st, _ = getstatusoutput(cmd)
              return True if st == 0 else False
        else:
           docker_cmd = 'docker exec cord-tester1'
           dhcpd_server_ip = get_controller()
           server_user = 'ubuntu'
           server_pass = 'ubuntu'
           service_satatus = True
           ssh_agent = SSHTestAgent(host = dhcpd_server_ip, user = server_user, password = server_user)
           if dhcpd == 'stop':
              status, output = ssh_agent.run_cmd('{} pkill -9 dhcpd'.format(docker_cmd))
              service_satatus = status and True
           elif dhcpd == 'start':
              for cmd in self.remote_dhcpd_cmd:
                 dhcpd_cmd = ' {0} /{1}'.format(docker_cmd,cmd)
                 status, output = ssh_agent.run_cmd(dhcpd_cmd)
                 service_satatus = status and True
           elif dhcpd == 'restart':
              status, output = ssh_agent.run_cmd('{} pkill -9 dhcpd'.format(docker_cmd))
              service_satatus = status and True
              for cmd in self.remote_dhcpd_cmd:
                 dhcpd_cmd = ' {0} /{1}'.format(docker_cmd,cmd)
                 status, output = ssh_agent.run_cmd(dhcpd_cmd)
                 service_satatus = status and True
           return service_satatus

    @classmethod
    def dhcp_l2_relay_setup(cls):
        device_details = OnosCtrl.get_devices(mfr = 'Nicira')
        if device_details is not None:
            did_ovs = device_details[0]['id']
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
            cls.onos_interface_load(interface_list)

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
    def cord_l2_relay_load(cls, dhcp_server_connectPoint = None, delete = False):
        ##read the current config
        current_netcfg = OnosCtrl.get_config()
        connect_points = set([])
        try:
            connect_points = set(current_netcfg['apps']['org.opencord.dhcpl2relay']['dhcpl2relay']['dhcpServerConnectPoints'])
        except KeyError, e:
            pass

        OnosCtrl.uninstall_app(cls.dhcpl2_app_file)
        relay_device_map = '{}/{}'.format(cls.relay_device_id, cls.relay_interface_port)
        #### We have to work on later versions by removing these hard coded values
        if dhcp_server_connectPoint is None:
            relay_device_present = filter(lambda cp: cp.split('/')[0] == cls.relay_device_id, connect_points)
            if not relay_device_present:
                connect_points.add(relay_device_map)
        else:
            cps_unused = map(lambda cp: connect_points.add(cp), dhcp_server_connectPoint)
        connect_points = list(connect_points)
        dhcp_dict = { "apps" : { "org.opencord.dhcpl2relay" : {"dhcpl2relay" :
                                   {"dhcpServerConnectPoints": connect_points}
                                                        }
                            }
                    }
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
             if device['available'] is True and device['driver'] == 'voltha':
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

    def cliEnter(self, controller = None):
        retries = 0
        while retries < 30:
            self.cli = OnosCliDriver(controller = controller, connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()


    def verify_cluster_status(self,controller = None,onos_instances=ONOS_INSTANCES,verify=False):
        tries = 0
        try:
            self.cliEnter(controller = controller)
            while tries <= 10:
                cluster_summary = json.loads(self.cli.summary(jsonFormat = True))
                if cluster_summary:
                    log_test.info("cluster 'summary' command output is %s"%cluster_summary)
                    nodes = cluster_summary['nodes']
                    if verify:
                        if nodes == onos_instances:
                            self.cliExit()
                            return True
                        else:
                            tries += 1
                            time.sleep(1)
                    else:
                        if nodes >= onos_instances:
                            self.cliExit()
                            return True
                        else:
                            tries += 1
                            time.sleep(1)
                else:
                    tries += 1
                    time.sleep(1)
            self.cliExit()
            return False
        except:
            raise Exception('Failed to get cluster members')
            return False


    def get_cluster_current_member_ips(self, controller = None, nodes_filter = None):
        tries = 0
        cluster_ips = []
        try:
            self.cliEnter(controller = controller)
            while tries <= 10:
                cluster_nodes = json.loads(self.cli.nodes(jsonFormat = True))
                if cluster_nodes:
                    log_test.info("cluster 'nodes' output is %s"%cluster_nodes)
                    if nodes_filter:
                        cluster_nodes = nodes_filter(cluster_nodes)
                    cluster_ips = map(lambda c: c['id'], cluster_nodes)
                    self.cliExit()
                    cluster_ips.sort(lambda i1,i2: int(i1.split('.')[-1]) - int(i2.split('.')[-1]))
                    return cluster_ips
                else:
                    tries += 1
            self.cliExit()
            return cluster_ips
        except:
            raise Exception('Failed to get cluster members')
            return cluster_ips

    def get_cluster_container_names_ips(self,controller=None):
        onos_names_ips = {}
        controllers = get_controllers()
        i = 0
        for controller in controllers:
            if i == 0:
                name = Onos.NAME
            else:
                name = '{}-{}'.format(Onos.NAME, i+1)
            onos_names_ips[controller] = name
            onos_names_ips[name] = controller
            i += 1
        return onos_names_ips

    def get_cluster_current_master_standbys(self,controller=None,device_id=relay_device_id):
        master = None
        standbys = []
        tries = 0
        try:
            cli = self.cliEnter(controller = controller)
            while tries <= 10:
                roles = json.loads(self.cli.roles(jsonFormat = True))
                log_test.info("cluster 'roles' command output is %s"%roles)
                if roles:
                    for device in roles:
                        log_test.info('Verifying device info in line %s'%device)
                        if device['id'] == device_id:
                            master = str(device['master'])
                            standbys = map(lambda d: str(d), device['standbys'])
                            log_test.info('Master and standbys for device %s are %s and %s'%(device_id, master, standbys))
                            self.cliExit()
                            return master, standbys
                            break
                    self.cliExit()
                    return master, standbys
                else:
                    tries += 1
                    time.sleep(1)
            self.cliExit()
            return master,standbys
        except:
            raise Exception('Failed to get cluster members')
            return master,standbys

    def get_cluster_current_master_standbys_of_connected_devices(self,controller=None):
        ''' returns master and standbys of all the connected devices to ONOS cluster instance'''
        device_dict = {}
        tries = 0
        try:
            cli = self.cliEnter(controller = controller)
            while tries <= 10:
                device_dict = {}
                roles = json.loads(self.cli.roles(jsonFormat = True))
                log_test.info("cluster 'roles' command output is %s"%roles)
                if roles:
                    for device in roles:
                        device_dict[str(device['id'])]= {'master':str(device['master']),'standbys':device['standbys']}
                        for i in range(len(device_dict[device['id']]['standbys'])):
                            device_dict[device['id']]['standbys'][i] = str(device_dict[device['id']]['standbys'][i])
                        log_test.info('master and standbys for device %s are %s and %s'%(device['id'],device_dict[device['id']]['master'],device_dict[device['id']]['standbys']))
                    self.cliExit()
                    return device_dict
                else:
                    tries += 1
                    time.sleep(1)
            self.cliExit()
            return device_dict
        except:
            raise Exception('Failed to get cluster members')
            return device_dict

    def get_number_of_devices_of_master(self,controller=None):
        '''returns master-device pairs, which master having what devices'''
        master_count = {}
        try:
            cli = self.cliEnter(controller = controller)
            masters = json.loads(self.cli.masters(jsonFormat = True))
            if masters:
                for master in masters:
                    master_count[str(master['id'])] = {'size':int(master['size']),'devices':master['devices']}
                return master_count
            else:
                return master_count
        except:
            raise Exception('Failed to get cluster members')
            return master_count

    def change_master_current_cluster(self,new_master=None,device_id=relay_device_id,controller=None):
        if new_master is None: return False
        self.cliEnter(controller=controller)
        cmd = 'device-role' + ' ' + device_id + ' ' + new_master + ' ' + 'master'
        command = self.cli.command(cmd = cmd, jsonFormat = False)
        self.cliExit()
        time.sleep(60)
        master, standbys = self.get_cluster_current_master_standbys(controller=controller,device_id=device_id)
        assert_equal(master,new_master)
        log_test.info('Cluster master changed to %s successfully'%new_master)

    def withdraw_cluster_current_mastership(self,master_ip=None,device_id=relay_device_id,controller=None):
        '''current master looses its mastership and hence new master will be elected'''
        self.cliEnter(controller=controller)
        cmd = 'device-role' + ' ' + device_id + ' ' + master_ip + ' ' + 'none'
        command = self.cli.command(cmd = cmd, jsonFormat = False)
        self.cliExit()
        time.sleep(60)
        new_master_ip, standbys = self.get_cluster_current_master_standbys(controller=controller,device_id=device_id)
        assert_not_equal(new_master_ip,master_ip)
        log_test.info('Device-role of device %s successfully changed to none for controller %s'%(device_id,master_ip))
        log_test.info('Cluster new master is %s'%new_master_ip)
        return True
    def cluster_controller_restarts(self, graceful = False):
        controllers = get_controllers()
        ctlr_len = len(controllers)
        if ctlr_len <= 1:
            log_test.info('ONOS is not running in cluster mode. This test only works for cluster mode')
            assert_greater(ctlr_len, 1)

        #this call would verify the cluster for once
        onos_map = self.get_cluster_container_names_ips()

        def check_exception(iteration, controller = None):
            adjacent_controller = None
            adjacent_controllers = None
            if controller:
                adjacent_controllers = list(set(controllers) - set([controller]))
                adjacent_controller = adjacent_controllers[0]
            for node in controllers:
                onosLog = OnosLog(host = node)
                ##check the logs for storage exception
                _, output = onosLog.get_log(('ERROR', 'Exception',))
                if output and output.find('StorageException$Timeout') >= 0:
                    log_test.info('\nStorage Exception Timeout found on node: %s\n' %node)
                    log_test.info('Dumping the ERROR and Exception logs for node: %s\n' %node)
                    log_test.info('\n' + '-' * 50 + '\n')
                    log_test.info('%s' %output)
                    log_test.info('\n' + '-' * 50 + '\n')
                    failed = self.verify_leaders(controllers)
                    if failed:
                        log_test.info('Leaders command failed on nodes: %s' %failed)
                        log_test.error('Test failed on ITERATION %d' %iteration)
                        CordLogger.archive_results(self._testMethodName,
                                                   controllers = controllers,
                                                   iteration = 'FAILED',
                                                   archive_partition = self.ARCHIVE_PARTITION)
                        assert_equal(len(failed), 0)
                    return controller

            try:
                ips = self.get_cluster_current_member_ips(controller = adjacent_controller)
                log_test.info('ONOS cluster formed with controllers: %s' %ips)
                st = True
            except:
                st = False

            failed = self.verify_leaders(controllers)
            if failed:
                log_test.error('Test failed on ITERATION %d' %iteration)
                CordLogger.archive_results(self._testMethodName,
                                           controllers = controllers,
                                           iteration = 'FAILED',
                                           archive_partition = self.ARCHIVE_PARTITION)
            assert_equal(len(failed), 0)
            if st is False:
                log_test.info('No storage exception and ONOS cluster was not formed successfully')
            else:
                controller = None

            return controller

        next_controller = None
        tries = self.ITERATIONS
        for num in range(tries):
            index = num % ctlr_len
            #index = random.randrange(0, ctlr_len)
            controller_name = onos_map[controllers[index]] if next_controller is None else onos_map[next_controller]
            controller = onos_map[controller_name]
            log_test.info('ITERATION: %d. Restarting Controller %s' %(num + 1, controller_name))
            try:
                #enable debug log for the other controllers before restarting this controller
                adjacent_controllers = list( set(controllers) - set([controller]) )
                self.log_set(controllers = adjacent_controllers)
                self.log_set(app = 'io.atomix', controllers = adjacent_controllers)
                if graceful is True:
                    log_test.info('Gracefully shutting down controller: %s' %controller)
                    self.onos_shutdown(controller)
                cord_test_onos_restart(node = controller, timeout = 0)
                self.log_set(controllers = controller)
                self.log_set(app = 'io.atomix', controllers = controller)
                time.sleep(60)
            except:
                time.sleep(5)
                continue

            #first archive the test case logs for this run
            CordLogger.archive_results(self._testMethodName,
                                       controllers = controllers,
                                       iteration = 'iteration_{}'.format(num+1),
                                       archive_partition = self.ARCHIVE_PARTITION)
            next_controller = check_exception(num, controller = controller)

    def onos_shutdown(self, controller = None):
        status = True
        self.cliEnter(controller = controller)
        try:
            self.cli.shutdown(timeout = 10)
        except:
            log_test.info('Graceful shutdown of ONOS failed for controller: %s' %controller)
            status = False

        self.cliExit()
        return status

    def test_dhcpl2relay_initialize(self):
        '''Configure the DHCP L2 relay app and start dhcpd'''
        self.dhcpd_start()

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
        connect_point = self.default_onos_netcfg['apps']['org.opencord.dhcpl2relay']['dhcpl2relay']['dhcpServerConnectPoints']
        log_test.info('Existing connect point of dhcp server is %s'%connect_point)
        relay_device_map1 = '{}/{}'.format(self.relay_device_id, random.randrange(1,5, 1))
        relay_device_map2 = '{}/{}'.format(self.relay_device_id, random.randrange(6,10, 1))
        relay_device_map3 = '{}/{}'.format(self.relay_device_id, random.randrange(10,16, 1))
        relay_device_map4 = '{}/{}'.format(self.relay_device_id, random.randrange(17,23, 1))
        dhcp_server_array_connectPoints = [connect_point[0],relay_device_map1,relay_device_map2,relay_device_map3,relay_device_map4]
        log_test.info('Added array of connect points of dhcp server is %s'%dhcp_server_array_connectPoints)

        mac = self.get_mac(iface)
        self.onos_load_config(self.default_onos_netcfg)
        dhcp_dict = { "apps" : { "org.opencord.dhcpl2relay" : {"dhcpl2relay" :
                                   {"dhcpServerConnectPoints": dhcp_server_array_connectPoints}
                                                        }
                            }
                    }
        self.onos_load_config(dhcp_dict)
        onos_netcfg = OnosCtrl.get_config()
        app_status = False
        app_name = 'org.opencord.dhcpl2relay'
        for app in onos_netcfg['apps']:
            if app == app_name and onos_netcfg['apps'][app] != {}:
               log_test.info('%s app is being installed'%app)
               log_test.info('The network configuration is shown %s'%onos_netcfg['apps'][app])
               x = set(onos_netcfg['apps'][app_name]['dhcpl2relay']['dhcpServerConnectPoints']) & set(dhcp_server_array_connectPoints)
               if len(x) == len(dhcp_server_array_connectPoints):
                  log_test.info('The loaded onos network configuration is = %s'%dhcp_server_array_connectPoints)
                  app_status = True
               break
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
        log_test.info('Uninstall the sadis app from onos ,app version = %s '%self.sadis_app_file)
        OnosCtrl.uninstall_app(self.sadis_app_file)
        OnosCtrl(self.sadis_app).deactivate()
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        assert_equal(cip,None)
        log_test.info('Installing the sadis app in onos again, app version = %s '%self.sadis_app_file)
        OnosCtrl.install_app(self.sadis_app_file)
        OnosCtrl(self.sadis_app).activate()
        OnosCtrl(self.app).activate()
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

        ### We can't test this on single uni port setup, hence its not to test
    @nottest
    def test_dhcpl2relay_with_N_requests(self, iface = 'veth0',requests=10):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        ip_map = {}
        for i in range(requests):
            #mac = RandMAC()._fix()
	    #log_test.info('mac is %s'%mac)
            cip, sip = self.send_recv(mac=mac, update_seed = True)
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

    @nottest
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

    @nottest
    def test_dhcpl2relay_starvation(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '182.17.0.1', iface = iface)
        log_test.info('Verifying 1 ')
	count = 0
        while True:
            #mac = RandMAC()._fix()
            cip, sip = self.send_recv(mac=mac,update_seed = True,validate = False)
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
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	log_test.info('Triggering DHCP discover again.')
	new_cip, new_sip, new_mac, _ = self.dhcp.only_discover(mac=mac)
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
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac,desired = True)
	assert_equal(cip,self.dhcp.seed_ip)
	log_test.info('Got dhcp client desired IP %s from server %s for mac %s as expected' %
		  (cip, sip, mac) )

    def test_dhcpl2relay_with_clients_desired_address_out_of_pool(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.35', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac,desired = True)
	assert_not_equal(cip,None)
	assert_not_equal(cip,self.dhcp.seed_ip)
	log_test.info('server offered IP from its pool when requested out of pool IP, as expected')

    def test_dhcpl2relay_nak_packet(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request('20.20.20.31', mac)
	assert_equal(new_cip, None)
	log_test.info('server sent NAK packet when requested other IP than that server offered')

    def test_dhcpl2relay_client_requests_with_specific_lease_time_in_discover_message(self, iface = 'veth0',lease_time=700):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '10.10.10.70', iface = iface)
	self.dhcp.return_option = 'lease'
	cip, sip, mac, lval = self.dhcp.only_discover(mac=mac,lease_time=True,lease_value=lease_time)
	assert_equal(lval, lease_time)
	log_test.info('dhcp server offered IP address with client requested lease time')

    def test_dhcpl2relay_with_client_request_after_reboot(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
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

    def test_dhcpl2relay_after_server_shutting_down(self, iface = 'veth0'):
        self.get_dhcpd_process()
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip, None)
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	log_test.info('server rebooting...')
        try:
         if self.dhcpd_stop(remote_controller = True, dhcpd = 'stop'):
           time.sleep(5)
	   log_test.info('DHCP server is stopped ')
	   new_cip, new_sip = self.dhcp.only_request(cip, mac)
           assert_equal(new_cip,None)
         else:
	   log_test.info('DHCP server is not stopped' )
           assert_equal(new_cip,None)
        finally:
          self.dhcpd_stop(remote_controller = True, dhcpd = 'restart')

    def test_dhcpl2relay_after_server_reboot(self, iface = 'veth0'):
        self.get_dhcpd_process()
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
        assert_not_equal(cip, None)
        new_cip, new_sip = self.dhcp.only_request(cip, mac)
        log_test.info('server rebooting...')
        try:
         if self.dhcpd_stop(remote_controller = True, dhcpd = 'restart'):
           time.sleep(5)
           log_test.info('DHCP server is rebooted')
           new_cip, new_sip = self.dhcp.only_request(cip, mac)
           assert_equal(new_cip,cip)
         else:
           log_test.info('DHCP server is not stopped' )
           assert_equal(new_cip,None)
        finally:
          self.dhcpd_stop(remote_controller = True, dhcpd = 'restart')

    def test_dhcpl2relay_after_server_stop_start(self, iface = 'veth0'):
        self.get_dhcpd_process()
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
        cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
        log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
                  (cip, sip, mac) )
        assert_not_equal(cip, None)
        new_cip, new_sip = self.dhcp.only_request(cip, mac)
        log_test.info('server rebooting...')
        try:
         if self.dhcpd_stop(remote_controller = True, dhcpd = 'stop'):
           time.sleep(5)
           log_test.info('DHCP server is stopped ')
           new_cip, new_sip = self.dhcp.only_request(cip, mac)
           assert_equal(new_cip,None)
         else:
           log_test.info('DHCP server is not stoppped' )
           assert_equal(new_cip,None)
         self.dhcpd_stop(remote_controller = True, dhcpd = 'start')
         log_test.info('DHCP server is started ')
         new_cip, new_sip = self.dhcp.only_request(cip, mac)
         assert_equal(new_cip, cip)
         log_test.info('client got same IP after server rebooted, as expected')
        finally:
          self.dhcpd_stop(remote_controller = True, dhcpd = 'restart')

    def test_dhcpl2relay_with_specific_lease_time_in_discover_and_without_in_request_packet(self, iface = 'veth0',lease_time=700):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	self.dhcp.return_option = 'lease'
	log_test.info('Sending DHCP discover with lease time of 700')
	cip, sip, mac, lval = self.dhcp.only_discover(mac=mac,lease_time = True, lease_value=lease_time)
	assert_equal(lval,lease_time)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True)
	assert_equal(new_cip,cip)
	assert_not_equal(lval, lease_time) #Negative Test Case
	log_test.info('client requested lease time in discover packer is not seen in server ACK packet as expected')

    def test_dhcpl2relay_with_specific_lease_time_in_request_and_without_in_discover_packet(self, iface = 'veth0',lease_time=800):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, lease_time = True,lease_value=lease_time)
	assert_equal(new_cip,cip)
	assert_equal(lval, lease_time)
	log_test.info('client requested lease time in request packet seen in servre replied ACK packet as expected')

    @nottest
    def test_dhcpl2relay_with_client_renew_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	new_cip, new_sip, lval = self.dhcp.only_request(cip, mac, renew_time = True)
	log_test.info('waiting for  renew  time.. a= %s b= %s c= %s'%(new_cip,new_sip,lval))
	time.sleep(lval)
	latest_cip, latest_sip = self.dhcp.only_request(new_cip, mac, unicast = True)
	assert_equal(latest_cip, cip)
	log_test.info('server renewed client IP when client sends request after renew time, as expected')

    @nottest
    def test_dhcpl2relay_with_client_rebind_time(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
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

	cip, sip, mac, subnet_mask = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(subnet_mask,expected_subnet)
	log_test.info('subnet mask in server offer packet is same as configured subnet mask in dhcp server')

    def test_dhcpl2relay_with_client_sending_dhcp_request_with_wrong_subnet_mask(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_not_equal(cip,None)
	self.dhcp.send_different_option = 'subnet'
	new_cip, new_sip = self.dhcp.only_request(cip, mac)
	assert_equal(new_cip, cip)
	log_test.info("Got DHCP Ack despite of specifying wrong Subnet Mask in DHCP Request.")

    @nottest
    def test_dhcpl2relay_with_client_expected_router_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
	expected_router_address = '20.20.20.1'
	self.dhcp.return_option = 'router'

	cip, sip, mac, router_address_value = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_router_address, router_address_value)
	log_test.info('router address in server offer packet is same as configured router address in dhcp server')

    @nottest
    def test_dhcpl2relay_with_client_sends_dhcp_request_with_wrong_router_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
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

	cip, sip, mac, broadcast_address_value = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_broadcast_address, broadcast_address_value)
	log_test.info('broadcast address in server offer packet is same as configured broadcast address in dhcp server')

    def test_dhcpl2relay_by_client_sending_dhcp_request_with_wrong_broadcast_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
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

	cip, sip, mac, dns_address_value = self.dhcp.only_discover(mac=mac)
	log_test.info('Got dhcp client IP %s from server %s for mac %s .' %
		  (cip, sip, mac) )
	assert_equal(expected_dns_address, dns_address_value)
	log_test.info('dns address in server offer packet is same as configured dns address in dhcp server')

    def test_dhcpl2relay_by_client_sending_request_with_wrong_dns_address(self, iface = 'veth0'):
        mac = self.get_mac(iface)
        self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)

	cip, sip, mac, _ = self.dhcp.only_discover(mac=mac)
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

    @nottest
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

    @nottest
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

    @nottest
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

    ##### All cluster scenarios on dhcpl2relay has to validate on voltha-setup from client server.
    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_cluster_master_change(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.change_master_current_cluster(device_id = self.relay_device_id,new_master=standbys[0])
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_cluster_master_withdraw_membership(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_member_ips(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.withdraw_cluster_current_mastership(device_id = self.relay_device_id,master_ip=master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_restart_cluster(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Restarting cluster whose master cluster= %s standby = %s'%(master, standbys))
        self.cord_test_onos_restart()
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_cluster_master_down(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Restarting cluster whose master cluster= %s standby = %s'%(master, standbys))
        cord_test_onos_shutdown(node = master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_cluster_standby_down(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        cord_test_onos_shutdown(node = standbys[0])
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_adding_two_members_to_cluster(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        cord_test_onos_shutdown(node = standbys[0])
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_releasing_dhcp_ip_after_restart_cluster_for_10_times(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Restarting cluster whose master cluster= %s standby = %s'%(master, standbys))
        for i in range(10):
            self.cord_test_onos_restart()
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_on_cluster_with_master_controller_only_restarts(self, iface = 'veth0'):
        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Restarting cluster whose master cluster= %s standby = %s'%(master, standbys))
        self.cord_test_onos_restart(node = master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_on_cluster_with_standby_controller_only_restarts(self, iface = 'veth0'):
        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Restarting cluster whose master cluster= %s standby = %s'%(master, standbys))
        self.cord_test_onos_restart(node = standbys[0])
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_by_removing_master_onos_instance(self, iface = 'veth0'):
        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_member_ips(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.withdraw_cluster_current_mastership(device_id = self.relay_device_id,master_ip=master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_by_removing_onos_instance_member(self, iface = 'veth0'):

        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_member_ips(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.withdraw_cluster_current_mastership(device_id = self.relay_device_id,master_ip=standbys[0])
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)

    @nottest
    def test_dhcpl2relay_by_toggle_master_onos_instance_membership(self, iface = 'veth0'):
        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_member_ips(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.withdraw_cluster_current_mastership(device_id = self.relay_device_id,master_ip=master)
        self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_by_toggle_standby_onos_instance_membership(self, iface = 'veth0'):
        pass
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_member_ips(device_id=self.relay_device_id)
        assert_equal(len(standbys),(onos_instances-1))
        mac = self.get_mac(iface)
        self.cord_l2_relay_load
        self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        cip, sip = self.send_recv(mac=mac)
        log_test.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
        self.withdraw_cluster_current_mastership(device_id = self.relay_device_id,master_ip=master)
        self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)
        self.cord_l2_relay_load
        log_test.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        try:
           assert_equal(self.dhcp.release(cip), True)
           log_test.info('Triggering DHCP discover again after release')
           self.cord_l2_relay_load
           cip2, sip2 = self.send_recv(mac=mac)
           log_test.info('Verifying released IP was given back on rediscover')
           assert_equal(cip, cip2)
           log_test.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
           assert_equal(self.dhcp.release(cip2), True)
        finally:
           self.change_master_current_cluster(device_id = self.relay_device_id,new_master=master)


    @nottest
    def test_dhcpl2relay_by_adding_onos_instance_member(self, iface = 'veth0'):
        pass



