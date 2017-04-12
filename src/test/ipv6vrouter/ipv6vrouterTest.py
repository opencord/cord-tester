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
from scapy.all import *
from CordTestUtils import get_mac, log_test
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnosFlowCtrl import OnosFlowCtrl
from onosclidriver import OnosCliDriver
#from quaggaclidriver import QuaggaCliDriver
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_quagga_restart, cord_test_quagga_stop, cord_test_quagga_shell
from portmaps import g_subscriber_port_map
from CordLogger import CordLogger
import threading
import time
import os
import json
import pexpect
import random
from netaddr.ip import IPNetwork, IPAddress

#from cli import quagga
#from quagga import *
#from cli import requires
#from cli import system
#from generic import *

log_test.setLevel('INFO')

class ipv6vrouter_exchange(CordLogger):

    apps = ('org.onosproject.vrouter', 'org.onosproject.fwd')
    device_id = 'of:' + get_mac()
    vrouter_device_dict = { "devices" : {
                "{}".format(device_id) : {
                    "basic" : {
                        "driver" : "softrouter"
                    }
                }
             },
          }
    zebra_conf = '''
password zebra
log stdout
service advanced-vty
!
!debug zebra rib
!debug zebra kernel
!debug zebra fpm
!
interface eth1
 ipv6 address 2001::10/32
line vty
 exec-timeout 0 0
'''

#! ip address 10.10.0.3/16
    test_path = os.path.dirname(os.path.realpath(__file__))
    quagga_config_path = os.path.join(test_path, '..', 'setup/quagga-config')
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '1000:10:0:0:0:0:0:164'
    INGRESS_PORT = 1
    EGRESS_PORT = 2
    MAX_PORTS = 100
    peer_list = [ ('2001:0:10:0:0:0:10:1', '00:00:00:00:00:01'), ('2001:0:20:0:0:0:20:1', '00:00:00:00:02:01'), ]
    network_list = []
    network_mask = 64
    default_routes_address = ('1001:0:10:0::/32',)
    default_peer_address = peer_list
    quagga_ip = os.getenv('QUAGGA_IP')

    @classmethod
    def setUpClass(cls):
        ''' Activate the vrouter apps'''
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        time.sleep(3)
        cls.load_device_id()

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the vrouter apps'''
        cls.vrouter_host_unload()
        cls.start_onos(network_cfg = {})

    @classmethod
    def load_device_id(cls):
        did = OnosCtrl.get_device_id()
        cls.device_id = did
        cls.vrouter_device_dict = { "devices" : {
                "{}".format(did) : {
                    "basic" : {
                        "driver" : "softrouter"
                    }
                }
            },
        }

    def cliEnter(self):
        retries = 0
        while retries < 3:
            self.cli = OnosCliDriver(connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

    @classmethod
    def onos_load_config(cls, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    @classmethod
    def vrouter_config_get(cls, networks = 4, peers = 1, peer_address = None,
                           route_update = None, router_address = None, specific_peer = None):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks, peers = peers,specific_peer = specific_peer,
                                                    peer_address = peer_address, router_address = router_address)
        return vrouter_configs

    @classmethod
    def host_config_load(cls, host_config = None):
        for host in host_config:
            status, code = OnosCtrl.host_config(host)
            if status is False:
                log_test.info('JSON request returned status %d' %code)
                assert_equal(status, True)

    @classmethod
    def generate_host_config(cls,hosts_list=None):
        num = 1
        hosts_dict = {}
	if hosts_list is not None:
	    hosts = hosts_list
	else:
	    hosts = cls.peer_list
        for host, mac in hosts:
            port = num  if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            hosts_dict[host] = {'mac':mac, 'vlan':'none', 'ipAddresses':[host], 'location':{ 'elementId' : '{}'.format(cls.device_id), 'port': port}}
            num += 1
            return hosts_dict.values()


    @classmethod
    def vrouter_host_load(cls, peer_address = None):
        index = 1
        peer_info = peer_address if peer_address is not None else cls.peer_list

        for host,_ in peer_info:
            iface = cls.port_map[index]
            index += 1
            log_test.info('Assigning ip %s to interface %s' %(host, iface))
            config_cmds = ( 'ifconfig {} 0'.format(iface),
                            'ifconfig {0} inet6 add {1}/64'.format(iface, host),
                            'arping -I {0} {1} -c 2'.format(iface, host),
                            )
            for cmd in config_cmds:
                os.system(cmd)

    @classmethod
    def vrouter_host_unload(cls, peer_address = None):
        index = 1
        peer_info = peer_address if peer_address is not None else cls.peer_list

        for host,_ in peer_info:
            iface = cls.port_map[index]
            index += 1
            config_cmds = ('ifconfig {} 0'.format(iface), )
            for cmd in config_cmds:
                os.system(cmd)

    @classmethod
    def start_onos(cls, network_cfg = None):
        if type(network_cfg) is tuple:
            res = []
            for v in network_cfg:
                res += v.items()
            config = dict(res)
        else:
            config = network_cfg
        log_test.info('Restarting ONOS with new network configuration %s'%config)
        return cord_test_onos_restart(config = config)

    @classmethod
    def randomipv6(cls, subnet='2001::', prefix=64):
	random.seed()
 	ipv6_address = IPAddress(subnet) + random.getrandbits(16)
	ipv6_network = IPNetwork(ipv6_address)
	ipv6_network.prefixlen = prefix
	output =  '{},{}'.format(ipv6_address,ipv6_network)
	return '{}'.format(ipv6_address),'{}'.format(ipv6_network)

    @classmethod
    def start_quagga(cls, networks = 4, peer_address = None, router_address = None):
	log_test.info('Peer address in quagga start is %s'%peer_address)
        log_test.info('Restarting Quagga container with configuration for %d networks' %(networks))
        config = cls.generate_conf(networks = networks, peer_address = peer_address, router_address = router_address)
        if networks <= 10000:
            boot_delay = 25
        else:
            delay_map = [60, 100, 150, 200, 300, 450, 600, 800, 1000, 1200]
            n = min(networks/100000, len(delay_map)-1)
            boot_delay = delay_map[n]
        cord_test_quagga_restart(config = config, boot_delay = boot_delay)

    @classmethod
    def generate_vrouter_conf(cls, networks = 4, peers = 1, peer_address = None, specific_peer = None,router_address = None):
	num = 0
	count = 0
	if peer_address is None:
	    start_peer =   ( 10 << 16 )
            end_peer =     ( 9999 << 16 )
	else:
	   ip = peer_address[0][0]
           start_ip = ip.split(':')
           start_peer =  ( int(start_ip[6]) << 16)
           end_peer =   ( 9999 << 16 )
	local_network = end_peer + 1
        ports_dict = { 'ports' : {} }
        interface_list = []
        peer_list = []
	for n in xrange(start_peer, end_peer, 65536):
	    port_map = ports_dict['ports']
            port = num+1  if count < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            device_port_key = '{0}/{1}'.format(cls.device_id, port)
	    try:
                interfaces = port_map[device_port_key]['interfaces']
            except:
                port_map[device_port_key] = { 'interfaces' : [] }
                interfaces = port_map[device_port_key]['interfaces']
	    if specific_peer is None:
                peer_ip = '2001:0:0:0:0:0:' + '%s:1'%( ( n >> 16 ) & 0xffff )
	    else:
		start_ip[6] = '%s'%( ( n >> 16 ) & 0xffff )
		start_ip[-1] = '1'
		peer_ip = ':'.join(start_ip)
	    peer_nt = peer_ip + '/112'
	    mac = RandMAC()._fix()
	    peer_list.append((peer_ip, mac))
	    log_test.info('peer ip is %s and and peer network is %s'%(peer_ip,peer_nt))
	    if num < cls.MAX_PORTS - 1:
                interface_dict = { 'name' : 'b1-{}'.format(port), 'ips': [peer_nt], 'mac' : mac }
                interfaces.append(interface_dict)
                interface_list.append(interface_dict['name'])
            else:
                interfaces[0]['ips'].append(peer_nt)
            num += 1
	    if num == peers:
		break
        quagga_dict = { 'apps': { 'org.onosproject.router' : { 'router' : {}, 'bgp' : { 'bgpSpeakers' : [] } } } }
        quagga_router_dict = quagga_dict['apps']['org.onosproject.router']['router']
        quagga_router_dict['ospfEnabled'] = True
        quagga_router_dict['interfaces'] = interface_list
        quagga_router_dict['controlPlaneConnectPoint'] = '{0}/{1}'.format(cls.device_id, peers + 1)

        #bgp_speaker_dict = { 'apps': { 'org.onosproject.router' : { 'bgp' : { 'bgpSpeakers' : [] } } } }
        bgp_speakers_list = quagga_dict['apps']['org.onosproject.router']['bgp']['bgpSpeakers']
        speaker_dict = {}
        speaker_dict['name'] = 'bgp{}'.format(peers+1)
        speaker_dict['connectPoint'] = '{0}/{1}'.format(cls.device_id, peers + 1)
        speaker_dict['peers'] = peer_list
        bgp_speakers_list.append(speaker_dict)
        cls.peer_list = peer_list
        return (cls.vrouter_device_dict, ports_dict, quagga_dict)


    @classmethod
    def generate_conf(cls, networks = 4, peer_address = None, router_address = None):
        num = 0
        if router_address is None:
            start_network =   ( 10 << 16 )
            end_network =     ( 9999 << 16 )
            network_mask = 112
        else:
           ip = router_address
           start_ip = ip.split(':')
           network_mask = int(start_ip[7].split('/')[1])
           start_network = (int(start_ip[6]) << 16)
           end_network = (9999 << 16)
        net_list = []
        peer_list = peer_address if peer_address is not None else cls.peer_list
        network_list = []
        for n in xrange(start_network, end_network, 65536):
	    if router_address is None:
                net = '3001:0:0:0:0:0:' + '%s:0'%( ( n >> 16 ) & 0xffff )
	    else:
		start_ip[6] = '%s'%( ( n >> 16 ) & 0xffff )
		net = ':'.join((start_ip[0],start_ip[1],start_ip[2],start_ip[3],start_ip[4],start_ip[5],start_ip[6],start_ip[7][0]))
            network_list.append(net)
            gateway = peer_list[num % len(peer_list)][0]
            net_route = 'ipv6 route {0}/{1} {2}'.format(net, network_mask, gateway)
            net_list.append(net_route)
            num += 1
            if num == networks:
                break
        cls.network_list = network_list
        cls.network_mask = network_mask
        zebra_routes = '\n'.join(net_list)
        return cls.zebra_conf + zebra_routes

    @classmethod
    def vrouter_activate(cls, deactivate = False):
        app = 'org.onosproject.vrouter'
        onos_ctrl = OnosCtrl(app)
        if deactivate is True:
            onos_ctrl.deactivate()
        else:
            onos_ctrl.activate()
        time.sleep(3)

    @classmethod
    def vrouter_configure(cls, networks = 4, peers = 1, peer_address = None,specific_peer = None,
                          route_update = None, router_address = None, time_expire = None, adding_new_routes = None):
        vrouter_configs = cls.vrouter_config_get(networks = networks, peers = peers,specific_peer = specific_peer,
                                                 peer_address = peer_address, route_update = route_update)
        cls.start_onos(network_cfg = vrouter_configs)
	hostcfg = cls.generate_host_config()
        cls.host_config_load(host_config = hostcfg)
        ##Start quagga
        cls.start_quagga(networks = networks, peer_address = peer_address, router_address = router_address)
        return vrouter_configs

    def vrouter_port_send_recv(self, ingress, egress, dst_mac, dst_ip, positive_test = True):
        src_mac = '00:00:00:00:00:02'
        src_ip = '1000:11:12:13:14:15:16:17'
        self.success = False if positive_test else True
        timeout = 10 if positive_test else 1
        count = 2 if positive_test else 1
        self.start_sending = True
        def recv_task():
            def recv_cb(pkt):
                log_test.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True if positive_test else False
            sniff(count=count, timeout=timeout,
                  lfilter = lambda p: IP in p and p[IP].dst == dst_ip and p[IP].src == src_ip,
                  prn = recv_cb, iface = self.port_map[ingress])
            self.start_sending = False

        t = threading.Thread(target = recv_task)
        t.start()
        L2 = Ether(src = src_mac, dst = dst_mac)
        L3 = IPv6(src=src_ip,dst = dst_ip)
        pkt = L2/L3
        log_test.info('Sending a packet with dst ip %s, dst mac %s on port %s to verify if flows are correct' %
                 (dst_ip, dst_mac, self.port_map[egress]))
        while self.start_sending is True:
            sendp(pkt, count=50, iface = self.port_map[egress])
        t.join()
        assert_equal(self.success, True)

    def vrouter_traffic_verify(self, positive_test = True, peer_address = None):
        if peer_address is None:
            peers = len(self.peer_list)
            peer_list = self.peer_list
        else:
            peers = len(peer_address)
            peer_list = peer_address
        egress = peers + 1
        num = 0
        num_hosts = 5 if positive_test else 1
        src_mac = '00:00:00:00:00:02'
        src_ip = '1000:11:12:13:14:15:16:17'
	last_bytes = [1234,8364,7360,'0af3','fdac']
        for network in self.network_list:
            num_ips = num_hosts
            octets = network.split(':')
            for  byte in last_bytes:
                octets[-1] = str(byte)
                dst_ip = ':'.join(octets)
                dst_mac = peer_list[ num % peers ] [1]
                port = (num % peers)
                ingress = port + 1
                #Since peers are on the same network
                ##Verify if flows are setup by sending traffic across
                self.vrouter_port_send_recv(ingress, egress, dst_mac, dst_ip, positive_test = positive_test)
            num += 1

    def __vrouter_network_verify(self, networks, peers = 1, positive_test = True,
                                 start_network = None, start_peer_address = None, route_update = None,
                                 invalid_peers = None, time_expire = None, unreachable_route_traffic = None,
                                 deactivate_activate_vrouter = None, adding_new_routes = None,
				 specific_peer = None):

        _, ports_map, egress_map = self.vrouter_configure(networks = networks, peers = peers,
                                                          peer_address = start_peer_address,
                                                          route_update = route_update,
                                                          router_address = start_network,
                                                          time_expire = time_expire,
                                                          adding_new_routes = adding_new_routes,
							  specific_peer = specific_peer)
	if self.network_list > 50:
		wait = len(self.network_list)/20
		time.sleep(wait)
		log_test.info('waiting for %d seconds to verify routes in ONOS'%wait)
	else:
		time.sleep(5)
	self.cliEnter()
	routes = json.loads(self.cli.routes(jsonFormat = True))
	assert_equal(len(routes['routes6']), networks)
	if invalid_peers is None:
            self.vrouter_traffic_verify()
	if time_expire is True:
            self.start_quagga(networks = networks, peer_address = start_peer_address, router_address = '12.10.10.1/24')
            self.vrouter_traffic_verify()
	if unreachable_route_traffic is True:
            network_list_backup = self.network_list
            self.network_list = ['1:1:1:1:1:1:1:1','2:2:2:2:2:2:2:2','3:3:3:3:3:3:3:3','4:4:4:4:4:4:4:4']
            self.vrouter_traffic_verify(positive_test = False)
            self.network_list = network_list_backup
	if deactivate_activate_vrouter is True:
            log_test.info('Deactivating vrouter app in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = True)
            #routes = json.loads(self.cli.routes(jsonFormat = False, cmd_exist = False))
            #assert_equal(len(routes['routes4']), 'Command not found')
            log_test.info('Activating vrouter app again in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = False)
	    if self.network_list > 50:
                wait = len(self.network_list)/20
                time.sleep(wait)
                log_test.info('waiting for %d seconds to verify routes in ONOS'%wait)
            else:
                time.sleep(5)
            routes = json.loads(self.cli.routes(jsonFormat = True))
            assert_equal(len(routes['routes4']), networks)
            self.vrouter_traffic_verify()
	self.cliExit()
        return True

    def __vrouter_network_verify_negative(self, networks, peers = 1):
        ##Stop quagga. Test traffic again to see if flows were removed
        log_test.info('Stopping Quagga container')
        cord_test_quagga_stop()
        self.vrouter_traffic_verify(positive_test = False)
        log_test.info('OVS flows have been removed successfully after Quagga was stopped')
        self.start_quagga(networks = networks)
        self.vrouter_traffic_verify()
        log_test.info('OVS flows have been successfully reinstalled after Quagga was restarted')

    def quagga_shell(self, cmd):
        shell_cmds = ('vtysh', '"conf t"', '"{}"'.format(cmd))
        quagga_cmd = ' -c '.join(shell_cmds)
        return cord_test_quagga_shell(quagga_cmd)

    def test_vrouter_ipv6_with_5_routes(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_5_routes_quagga_restart_without_config(self):
	res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('Restart Quagga container without config retain')
        cord_test_quagga_restart()
        self.vrouter_traffic_verify(positive_test = False)

    def test_vrouter_ipv6_with_5_routes_quagga_restart_with_config(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after Quagga restart with config retain')
        #cord_test_quagga_restart()
        self.start_quagga(networks=5)
        self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_ipv6_with_5_routes_quagga_stop(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after Quagga stop')
        cord_test_quagga_stop()
        self.vrouter_traffic_verify(positive_test = False)

    def test_vrouter_ipv6_with_5_routes_quagga_stop_and_start(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after Quagga stop and start again')
        cord_test_quagga_stop()
        self.vrouter_traffic_verify(positive_test = False)
	self.start_quagga(networks=5)
	self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_ipv6_with_5_routes_onos_restart_without_config(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after ONOS restart without config retain')
	cord_test_onos_restart()
        self.vrouter_traffic_verify(positive_test = False)

    def test_vrouter_ipv6_with_5_routes_onos_restart_with_config(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after ONOS restart with config retain')
	vrouter_configs = self.vrouter_config_get(networks = 5, peers = 1,
                                                 peer_address = None, route_update = None)
        self.start_onos(network_cfg=vrouter_configs)
	mac = RandMAC()._fix()
	hostcfg = self.generate_host_config(hosts_list = [('2001:0:0:0:0:0:10:1',mac)])
        self.host_config_load(host_config = hostcfg)
	time.sleep(10)
        self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_ipv6_with_5_routes_restart_quagga_and_onos_with_config(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)
        log_test.info('verifying vrouter traffic after Quagga and ONOS restart with config retain')
	#cord_test_quagga_restart()
	self.start_quagga(networks=5)
        vrouter_configs = self.vrouter_config_get(networks = 5, peers = 1,
                                                 peer_address = None, route_update = None)
        self.start_onos(network_cfg = vrouter_configs)
        mac = RandMAC()._fix()
	hostcfg = self.generate_host_config(hosts_list = [('2001:0:0:0:0:0:10:1',mac)])
        self.host_config_load(host_config = hostcfg)
        time.sleep(10)
        self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_ipv6_with_5_routes_2_peers(self):
        res = self.__vrouter_network_verify(5, peers = 2)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_6_routes_3_peers(self):
        res = self.__vrouter_network_verify(6, peers = 3)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_50_routes(self):
        res = self.__vrouter_network_verify(50, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_50_routes_5_peers(self):
        res = self.__vrouter_network_verify(50, peers = 5)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_100_routes(self):
        res = self.__vrouter_network_verify(100, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_100_routes_10_peers(self):
        res = self.__vrouter_network_verify(100, peers = 10)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_300_routes(self):
        res = self.__vrouter_network_verify(300, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_1k_routes(self):
        res = self.__vrouter_network_verify(1000, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_9k_routes(self):
        res = self.__vrouter_network_verify(9000, peers = 1)
        assert_equal(res, True)

    @nottest # Need to implement logic for generating more than 10000 routes
    def test_vrouter_ipv6_with_100000_routes(self):
        res = self.__vrouter_network_verify(100000, peers = 1)
        assert_equal(res, True)

    @nottest # Need to implement logic for generating more than 10000 routes
    def test_vrouter_ipv6_with_1000000_routes(self):
        res = self.__vrouter_network_verify(1000000, peers = 1)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_route_update(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        assert_equal(res, True)
        peer_info = [('2001:0:0:0:0:0:72:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:73:1', '00:00:00:00:02:01')]
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, route_update = True)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_64bit_mask_route_update(self):
        router_address = '3001:0:0:0:0:0:56:0/64'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_32bit_route_update(self):
        router_address = '3112:90c4:836a:7e56:0:0:06:0/32'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_16bit_route_update(self):
        router_address = '9961:9474:0:8472:f30a:0:06:0/16'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True,start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_48bit_route_update(self):
        router_address = 'c34a:9737:14cd:8730:0:0:06:0/48'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_classless_route_update(self):
        router_address = '3001:430d:76cb:f56e:873:0:677:0/67'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_classless_duplicate_route_update(self):
        router_address = '3001:8730:732:723:0:0:677:0/116'
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_invalid_peers(self):
        peer_info = [('FE80:0:0:0:C800:27FF:10:8', '00:00:00:00:01:01'), ('FE80:0:0:0:C800:27FF:11:8', '00:00:00:00:02:01')]
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, specific_peer=True,invalid_peers= True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_traffic_sent_between_peers_connected_to_onos(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, traffic_running_between_peers = True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_routes_time_expire(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, time_expire = True)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_unreachable_route(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, unreachable_route_traffic = True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_ipv6_with_enabling_disabling_vrouter_app(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, deactivate_activate_vrouter = True)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_adding_new_routes_in_routing_table(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        cmd = 'ipv6 route 4001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:10:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify()
        self.network_list = [ '4001:0:0:0:0:0:677:0' ]
        self.network_mask = 64
        self.vrouter_traffic_verify()
        assert_equal(res, True)

    def test_vrouter_ipv6_with_adding_new_routes_in_quagga_routing_table_and_restart(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        cmd = 'ipv6 route 4001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:10:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify()
        self.network_list = [ '4001:0:0:0:0:0:677:0' ]
        self.network_mask = 64
        self.vrouter_traffic_verify()
	log_test.info('verifying vrouter traffic for added  routes after Quagga restart with old config only retain')
        #cord_test_quagga_restart()
        self.start_quagga(networks=5)
        self.vrouter_traffic_verify(positive_test = False)
        assert_equal(res, True)

    def test_vrouter_ipv6_with_removing_old_routes_in_routing_table(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        cmd = 'ipv6 route 4001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:10:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify()
        old_network_list = self.network_list
        old_network_mask = self.network_mask
        self.network_list = [ '4001:0:0:0:0:0:677:0' ]
        self.network_mask = 64
        self.vrouter_traffic_verify()
        assert_equal(res, True)
        cmd = 'no ipv6 route 4001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:10:1'
        self.quagga_shell(cmd)
        time.sleep(5)
        self.vrouter_traffic_verify(positive_test = False)
        self.network_mask = old_network_mask
        self.network_list = old_network_list
        self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_ipv6_modifying_nexthop_route_in_routing_table(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/112'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:677:0/112 2001:0:0:0:0:0:18:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)


    def test_vrouter_ipv6_deleting_alternative_nexthop_in_routing_table(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/112'
        res = self.__vrouter_network_verify(1, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:677:0/112 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        time.sleep(5)
        self.vrouter_traffic_verify(positive_test = False)
        assert_equal(res, True)

    def test_vrouter_ipv6_deleting_some_routes_in_routing_table(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/112'
        res = self.__vrouter_network_verify(10, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:677:0/112 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:678:0/112 2001:0:0:0:0:0:13:1'
        self.quagga_shell(cmd)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:679:0/112 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)

    def test_vrouter_ipv6_deleting_some_routes_in_quagga_routing_table_and_restart(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/112'
        res = self.__vrouter_network_verify(10, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:677:0/112 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:678:0/112 2001:0:0:0:0:0:13:1'
        self.quagga_shell(cmd)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:679:0/112 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
	self.network_list = [ '3001:0:0:0:0:0:677:0','3001:0:0:0:0:0:678:0','3001:0:0:0:0:0:679:0' ]
	self.network_mask = 112
        self.vrouter_traffic_verify(positive_test = False)
	self.network_list = [ '3001:0:0:0:0:0:680:0','3001:0:0:0:0:0:681:0' ]
        self.vrouter_traffic_verify(positive_test = True)
	#cord_test_quagga_restart()
        self.start_quagga(networks=10)
	self.network_list = [ '3001:0:0:0:0:0:677:0','3001:0:0:0:0:0:681:0' ]
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)


    def test_vrouter_ipv6_deleting_and_adding_routes_in_routing_table(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/64'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ipv6 route 3001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        cmd = 'ipv6 route 3001:0:0:0:0:0:677:0/64 2001:0:0:0:0:0:12:1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)

    def test_vrouter_ipv6_toggling_nexthop_interface(self):
        peer_info = [('2001:0:0:0:0:0:12:1', '00:00:00:00:01:01'), ('2001:0:0:0:0:0:13:1', '00:00:00:00:02:01')]
        router_address = '3001:0:0:0:0:0:677:0/64'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_peer_address = peer_info, start_network  = router_address)
        iface = self.port_map[1]
        #toggle the interface to trigger host removal.
        cmds = ('ifconfig {} down'.format(iface),
                'sleep 2',
                'ifconfig {} 0'.format(iface),)
        for cmd in cmds:
            os.system(cmd)
        self.vrouter_traffic_verify(positive_test = False)
        host = "2001:0:0:0:0:0:12:1"
        cmd = 'ifconfig {0} {1} up'.format(iface, host)
        os.system(cmd)
        #wait for arp refresh
        time.sleep(60)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)
