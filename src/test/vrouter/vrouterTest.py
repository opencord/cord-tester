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
from CordTestUtils import get_mac
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

#from cli import quagga
#from quagga import *
#from cli import requires
#from cli import system
#from generic import *

log.setLevel('INFO')

class vrouter_exchange(CordLogger):

    apps = ('org.onosproject.proxyarp', 'org.onosproject.hostprovider', 'org.onosproject.vrouter', 'org.onosproject.fwd')
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
!interface eth1
! ip address 10.10.0.3/16
line vty
 exec-timeout 0 0
'''
    test_path = os.path.dirname(os.path.realpath(__file__))
    quagga_config_path = os.path.join(test_path, '..', 'setup/quagga-config')
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '192.168.10.50'
    INGRESS_PORT = 1
    EGRESS_PORT = 2
    MAX_PORTS = 100
    peer_list = [ ('192.168.10.1', '00:00:00:00:00:01'), ('192.168.11.1', '00:00:00:00:02:01'), ]
    network_list = []
    network_mask = 24
    default_routes_address = ('11.10.10.0/24',)
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
        #cls.vrouter_host_unload()
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

    @classmethod
    def activate_apps(cls, deactivate = False):
        for app in cls.apps:
            onos_ctrl = OnosCtrl(app)
            if deactivate is False:
                onos_ctrl.activate()
            else:
                onos_ctrl.deactivate()
            time.sleep(2)

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
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    @classmethod
    def vrouter_config_get(cls, networks = 4, peers = 1, peer_address = None,
                           route_update = None, router_address = None):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks, peers = peers,
                                                    peer_address = peer_address, router_address = router_address)
        return vrouter_configs
        ##ONOS router does not support dynamic reconfigurations
        #for config in vrouter_configs:
        #    cls.onos_load_config(config)
        #    time.sleep(5)

    @classmethod
    def vrouter_host_load(cls, peer_address = None):
        index = 1
        peer_info = peer_address if peer_address is not None else cls.peer_list

        for host,_ in peer_info:
            iface = cls.port_map[index]
            index += 1
            log.info('Assigning ip %s to interface %s' %(host, iface))
            config_cmds = ( 'ifconfig {} 0'.format(iface),
                            'ifconfig {0} {1}'.format(iface, host),
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
        log.info('Restarting ONOS with new network configuration')
        return cord_test_onos_restart(config = config)

    @classmethod
    def start_quagga(cls, networks = 4, peer_address = None, router_address = None):
        log.info('Restarting Quagga container with configuration for %d networks' %(networks))
        config = cls.generate_conf(networks = networks, peer_address = peer_address, router_address = router_address)
        if networks <= 10000:
            boot_delay = 25
        else:
            delay_map = [60, 100, 150, 200, 300, 450, 600, 800, 1000, 1200]
            n = min(networks/100000, len(delay_map)-1)
            boot_delay = delay_map[n]
        cord_test_quagga_restart(config = config, boot_delay = boot_delay)

    @classmethod
    def generate_vrouter_conf(cls, networks = 4, peers = 1, peer_address = None, router_address = None):
        num = 0
        if peer_address is None:
           start_peer = ( 192 << 24) | ( 168 << 16)  |  (10 << 8) | 0
           end_peer =   ( 200 << 24 ) | (168 << 16)  |  (10 << 8) | 0
        else:
           ip = peer_address[0][0]
           start_ip = ip.split('.')
           start_peer = ( int(start_ip[0]) << 24) | ( int(start_ip[1]) << 16)  |  ( int(start_ip[2]) << 8) | 0
           end_peer =   ((int(start_ip[0]) + 8) << 24 ) | (int(start_ip[1]) << 16)  |  (int(start_ip[2]) << 8) | 0
        local_network = end_peer + 1
        ports_dict = { 'ports' : {} }
        interface_list = []
        peer_list = []
        for n in xrange(start_peer, end_peer, 256):
            port_map = ports_dict['ports']
            port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            device_port_key = '{0}/{1}'.format(cls.device_id, port)
            try:
                interfaces = port_map[device_port_key]['interfaces']
            except:
                port_map[device_port_key] = { 'interfaces' : [] }
                interfaces = port_map[device_port_key]['interfaces']
            ip = n + 2
            peer_ip = n + 1
            ips = '%d.%d.%d.%d/24'%( (ip >> 24) & 0xff, ( (ip >> 16) & 0xff ), ( (ip >> 8 ) & 0xff ), ip & 0xff)
            peer = '%d.%d.%d.%d' % ( (peer_ip >> 24) & 0xff, ( ( peer_ip >> 16) & 0xff ), ( (peer_ip >> 8 ) & 0xff ), peer_ip & 0xff )
            mac = RandMAC()._fix()
            peer_list.append((peer, mac))
            if num < cls.MAX_PORTS - 1:
                interface_dict = { 'name' : 'b1-{}'.format(port), 'ips': [ips], 'mac' : mac }
                interfaces.append(interface_dict)
                interface_list.append(interface_dict['name'])
            else:
                interfaces[0]['ips'].append(ips)
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
            start_network = ( 11 << 24) | ( 10 << 16) | ( 10 << 8) | 0
            end_network =   ( 172 << 24 ) | ( 0 << 16)  | (0 << 8) | 0
            network_mask = 24
        else:
           ip = router_address
           start_ip = ip.split('.')
           network_mask = int(start_ip[3].split('/')[1])
           start_ip[3] = (start_ip[3].split('/'))[0]
           start_network = (int(start_ip[0]) << 24) | ( int(start_ip[1]) << 16)  |  ( int(start_ip[2]) << 8) | 0
           end_network = (172 << 24 ) | (int(start_ip[1]) << 16)  |  (int(start_ip[2]) << 8) | 0
        net_list = []
        peer_list = peer_address if peer_address is not None else cls.peer_list
        network_list = []
        for n in xrange(start_network, end_network, 256):
            net = '%d.%d.%d.0'%( (n >> 24) & 0xff, ( ( n >> 16) & 0xff ), ( (n >> 8 ) & 0xff ) )
            network_list.append(net)
            gateway = peer_list[num % len(peer_list)][0]
            net_route = 'ip route {0}/{1} {2}'.format(net, network_mask, gateway)
            net_list.append(net_route)
            num += 1
            if num == networks:
                break
        cls.network_list = network_list
        cls.network_mask = network_mask
        zebra_routes = '\n'.join(net_list)
        #log.info('Zebra routes: \n:%s\n' %cls.zebra_conf + zebra_routes)
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
    def vrouter_configure(cls, networks = 4, peers = 1, peer_address = None,
                          route_update = None, router_address = None, time_expire = None, adding_new_routes = None):
        vrouter_configs = cls.vrouter_config_get(networks = networks, peers = peers,
                                                 peer_address = peer_address, route_update = route_update)
        cls.start_onos(network_cfg = vrouter_configs)
        cls.activate_apps()
        time.sleep(5)
        cls.vrouter_host_load()
        ##Start quagga
        cls.start_quagga(networks = networks, peer_address = peer_address, router_address = router_address)
        return vrouter_configs

    def vrouter_port_send_recv(self, ingress, egress, dst_mac, dst_ip, positive_test = True):
        src_mac = '00:00:00:00:00:02'
        src_ip = '1.1.1.1'
        self.success = False if positive_test else True
        timeout = 10 if positive_test else 1
        count = 2 if positive_test else 1
        self.start_sending = True
        def recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True if positive_test else False
            sniff(count=count, timeout=timeout,
                  lfilter = lambda p: IP in p and p[IP].dst == dst_ip and p[IP].src == src_ip,
                  prn = recv_cb, iface = self.port_map[ingress])
            self.start_sending = False

        t = threading.Thread(target = recv_task)
        t.start()
        L2 = Ether(src = src_mac, dst = dst_mac)
        L3 = IP(src = src_ip, dst = dst_ip)
        pkt = L2/L3
        log.info('Sending a packet with dst ip %s, dst mac %s on port %s to verify if flows are correct' %
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
        src_ip = '1.1.1.1'
        if self.network_mask != 24:
            peers = 1
        for network in self.network_list:
            num_ips = num_hosts
            octets = network.split('.')
            for i in xrange(num_ips):
                octets[-1] = str(int(octets[-1]) + 1)
                dst_ip = '.'.join(octets)
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
                                 deactivate_activate_vrouter = None, adding_new_routes = None):

        _, ports_map, egress_map = self.vrouter_configure(networks = networks, peers = peers,
                                                          peer_address = start_peer_address,
                                                          route_update = route_update,
                                                          router_address = start_network,
                                                          time_expire = time_expire,
                                                          adding_new_routes = adding_new_routes)
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        ##We read from cli if we expect less number of routes to avoid cli timeouts
        if networks <= 10000:
            routes = json.loads(self.cli.routes(jsonFormat = True))
            #log.info('Routes: %s' %routes)
            if start_network is not None:
               if start_network.split('/')[1] is 24:
                  assert_equal(len(routes['routes4']), networks)
               if start_network.split('/')[1] is not 24:
                  assert_equal(len(routes['routes4']), 1)
            if start_network is None and invalid_peers is None:
               assert_equal(len(routes['routes4']), networks)
            if invalid_peers is not None:
               assert_equal(len(routes['routes4']), 0)
            flows = json.loads(self.cli.flows(jsonFormat = True))
            flows = filter(lambda f: f['flows'], flows)
            #log.info('Flows: %s' %flows)
            assert_not_equal(len(flows), 0)
        if invalid_peers is None:
            self.vrouter_traffic_verify()
        if positive_test is False:
            self.__vrouter_network_verify_negative(networks, peers = peers)
        if time_expire is True:
            self.start_quagga(networks = networks, peer_address = start_peer_address, router_address = '12.10.10.1/24')
            self.vrouter_traffic_verify()
        if unreachable_route_traffic is True:
            network_list_backup = self.network_list
            self.network_list = ['2.2.2.2','3.3.3.3','4.4.4.4','5.5.5.5']
            self.vrouter_traffic_verify(positive_test = False)
            self.network_list = network_list_backup
        if deactivate_activate_vrouter is True:
            log.info('Deactivating vrouter app in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = True)
            #routes = json.loads(self.cli.routes(jsonFormat = False, cmd_exist = False))
            #assert_equal(len(routes['routes4']), 'Command not found')
            log.info('Activating vrouter app again in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = False)
            routes = json.loads(self.cli.routes(jsonFormat = True))
            assert_equal(len(routes['routes4']), networks)
            self.vrouter_traffic_verify()
        self.cliExit()
        self.vrouter_host_unload()
        return True

    def __vrouter_network_verify_negative(self, networks, peers = 1):
        ##Stop quagga. Test traffic again to see if flows were removed
        log.info('Stopping Quagga container')
        cord_test_quagga_stop()
        if networks <= 10000:
            routes = json.loads(self.cli.routes(jsonFormat = True))
            #Verify routes have been removed
            if routes and routes.has_key('routes4'):
                assert_equal(len(routes['routes4']), 0)
        self.vrouter_traffic_verify(positive_test = False)
        log.info('OVS flows have been removed successfully after Quagga was stopped')
        self.start_quagga(networks = networks)
        ##Verify the flows again after restarting quagga back
        if networks <= 10000:
            routes = json.loads(self.cli.routes(jsonFormat = True))
            assert_equal(len(routes['routes4']), networks)
        self.vrouter_traffic_verify()
        log.info('OVS flows have been successfully reinstalled after Quagga was restarted')

    def quagga_shell(self, cmd):
        shell_cmds = ('vtysh', '"conf t"', '"{}"'.format(cmd))
        quagga_cmd = ' -c '.join(shell_cmds)
        return cord_test_quagga_shell(quagga_cmd)

    def test_vrouter_with_5_routes(self):
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_5_routes_2_peers(self):
        res = self.__vrouter_network_verify(5, peers = 2)
        assert_equal(res, True)

    def test_vrouter_with_6_routes_3_peers(self):
        res = self.__vrouter_network_verify(6, peers = 3)
        assert_equal(res, True)

    def test_vrouter_with_50_routes(self):
        res = self.__vrouter_network_verify(50, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_50_routes_5_peers(self):
        res = self.__vrouter_network_verify(50, peers = 5)
        assert_equal(res, True)

    def test_vrouter_with_100_routes(self):
        res = self.__vrouter_network_verify(100, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_100_routes_10_peers(self):
        res = self.__vrouter_network_verify(100, peers = 10)
        assert_equal(res, True)

    def test_vrouter_with_300_routes(self):
        res = self.__vrouter_network_verify(300, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_1000_routes(self):
        res = self.__vrouter_network_verify(1000, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_10000_routes(self):
        res = self.__vrouter_network_verify(10000, peers = 1)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_100000_routes(self):
        res = self.__vrouter_network_verify(100000, peers = 1)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_1000000_routes(self):
        res = self.__vrouter_network_verify(1000000, peers = 1)
        assert_equal(res, True)

    def test_vrouter_with_5_routes_stopping_quagga(self):
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = False)

    def test_vrouter_with_50_routes_stopping_quagga(self):
        res = self.__vrouter_network_verify(50, peers = 1, positive_test = False)

    def test_vrouter_with_route_update(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        assert_equal(res, True)
        peer_info = [('192.168.20.1', '00:00:00:00:01:01'), ('192.168.21.1', '00:00:00:00:02:01')]
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, route_update = True)
        assert_equal(res, True)

    def test_vrouter_with_classA_route_update(self):
        router_address = '11.10.10.0/8'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_classB_route_update(self):
        router_address = '11.10.10.0/16'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_classless_route_update(self):
        router_address = '11.10.10.0/12'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_classA_duplicate_route_update(self):
        router_address = '11.10.10.0/8'
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_classB_duplicate_route_update(self):
        router_address = '11.10.10.0/16'
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_classless_duplicate_route_update(self):
        router_address = '11.10.10.0/12'
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = True, start_network = router_address)
        assert_equal(res, True)

    def test_vrouter_with_invalid_peers(self):
        peer_info = [('239.255.255.250', '00:00:00:00:01:01'), ('239.255.255.240', '00:00:00:00:02:01')]
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, invalid_peers= True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_traffic_sent_between_peers_connected_to_onos(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, traffic_running_between_peers = True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_routes_time_expire(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, time_expire = True)
        assert_equal(res, True)

    def test_vrouter_with_unreachable_route(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, unreachable_route_traffic = True)
        assert_equal(res, True)

    @nottest
    def test_vrouter_with_enabling_disabling_vrouter_app(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True, deactivate_activate_vrouter = True)
        assert_equal(res, True)

    def test_vrouter_with_adding_new_routes_in_routing_table(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        cmd = 'ip route 21.10.20.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify()
        self.network_list = [ '21.10.20.0' ]
        self.network_mask = 24
        self.vrouter_traffic_verify()
        assert_equal(res, True)

    def test_vrouter_with_removing_old_routes_in_routing_table(self):
        res = self.__vrouter_network_verify(5, peers = 2, positive_test = True)
        cmd = 'ip route 21.10.20.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify()
        old_network_list = self.network_list
        old_network_mask = self.network_mask
        self.network_list = [ '21.10.20.0' ]
        self.network_mask = 24
        self.vrouter_traffic_verify()
        assert_equal(res, True)
        cmd = 'no ip route 21.10.20.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        time.sleep(5)
        self.vrouter_traffic_verify(positive_test = False)
        self.network_mask = old_network_mask
        self.network_list = old_network_list
        self.vrouter_traffic_verify(positive_test = True)

    def test_vrouter_modifying_nexthop_route_in_routing_table(self):
        peer_info = [('192.168.10.1', '00:00:00:00:01:01'), ('192.168.11.1', '00:00:00:00:02:01')]
        router_address = '11.10.10.0/24'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'ip route 11.10.10.0/24 192.168.20.1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)


    def test_vrouter_deleting_alternative_nexthop_in_routing_table(self):
        peer_info = [('192.168.10.1', '00:00:00:00:01:01'), ('192.168.11.1', '00:00:00:00:02:01')]
        router_address = '11.10.10.0/24'
        res = self.__vrouter_network_verify(1, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ip route 11.10.10.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        time.sleep(5)
        self.vrouter_traffic_verify(positive_test = False)
        assert_equal(res, True)

    def test_vrouter_deleting_some_routes_in_routing_table(self):
        peer_info = [('192.168.10.1', '00:00:00:00:01:01'), ('192.168.11.1', '00:00:00:00:02:01')]
        router_address = '11.10.10.0/24'
        res = self.__vrouter_network_verify(10, peers = 2, positive_test = True,
                                            start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ip route 11.10.10.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        cmd = 'no ip route 11.10.13.0/24 192.168.11.1'
        self.quagga_shell(cmd)
        cmd = 'no ip route 11.10.14.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)


    def test_vrouter_deleting_and_adding_routes_in_routing_table(self):
        peer_info = [('192.168.10.1', '00:00:00:00:01:01'), ('192.168.11.1', '00:00:00:00:02:01')]
        router_address = '11.10.10.0/24'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_peer_address = peer_info, start_network  = router_address)
        cmd = 'no ip route 11.10.10.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        cmd = 'ip route 11.10.10.0/24 192.168.10.1'
        self.quagga_shell(cmd)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)

    def test_vrouter_toggling_nexthop_interface(self):
        peer_info = [('192.168.10.1', '00:00:00:00:01:01'), ('192.168.11.1', '00:00:00:00:02:01')]
        router_address = '11.10.10.0/24'
        res = self.__vrouter_network_verify(1, peers = 1, positive_test = True, start_peer_address = peer_info, start_network  = router_address)
        iface = self.port_map[1]
        #toggle the interface to trigger host removal.
        cmds = ('ifconfig {} down'.format(iface),
                'sleep 2',
                'ifconfig {} 0'.format(iface),)
        for cmd in cmds:
            os.system(cmd)
        self.vrouter_traffic_verify(positive_test = False)
        host = "192.168.10.1"
        cmd = 'ifconfig {0} {1} up'.format(iface, host)
        os.system(cmd)
        #wait for arp refresh
        time.sleep(60)
        self.vrouter_traffic_verify(positive_test = True)
        assert_equal(res, True)
