import unittest
from nose.tools import *
from scapy.all import *
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnosFlowCtrl import OnosFlowCtrl, get_mac
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_quagga_restart
from portmaps import g_subscriber_port_map
import threading
import time
import os
import json
log.setLevel('INFO')

class QuaggaStopWrapper(Container):

    def __init__(self, name = 'cord-quagga', image = 'cord-test/quagga', tag = 'latest'):
        super(QuaggaStopWrapper, self).__init__(name, image, tag = tag)
        if self.exists():
            self.kill()

class vrouter_exchange(unittest.TestCase):

    apps = ('org.onosproject.vrouter', 'org.onosproject.fwd')
    device_id = 'of:' + get_mac('ovsbr0')
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

    @classmethod
    def setUpClass(cls):
        ''' Activate the vrouter apps'''
        cls.olt = OltConfig()
        cls.port_map = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        #cls.vrouter_host_load(host = cls.GATEWAY)
        time.sleep(3)
        
    @classmethod
    def tearDownClass(cls):
        '''Deactivate the vrouter apps'''
        #cls.vrouter_host_unload()

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
    def vrouter_config_get(cls, networks = 4, peers = 1):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks, peers = peers)
        return vrouter_configs
        ##ONOS router does not support dynamic reconfigurations
        #for config in vrouter_configs:
        #    cls.onos_load_config(config)
        #    time.sleep(5)

    @classmethod
    def vrouter_host_load(cls):
        index = 1
        for host,_ in cls.peer_list:
            iface = cls.port_map[index]
            index += 1
            config_cmds = ( 'ifconfig {0} {1}'.format(iface, host),
                            'arping -I {0} {1} -c 2'.format(iface, host),
                            )
            for cmd in config_cmds:
                os.system(cmd)

    @classmethod
    def vrouter_host_unload(cls):
        index = 1
        for host,_ in cls.peer_list:
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
        cfg = json.dumps(config)
        with open('{}/network-cfg.json'.format(cls.onos_config_path), 'w') as f:
            f.write(cfg)

        return cord_test_onos_restart()

    @classmethod
    def start_quagga(cls, networks = 4):
        log.info('Restarting Quagga container with configuration for %d networks' %(networks))
        config = cls.generate_conf(networks = networks)
        host_config_file = '{}/testrib_gen.conf'.format(Quagga.host_quagga_config)
        guest_config_file = os.path.join(Quagga.guest_quagga_config, 'testrib_gen.conf')
        with open(host_config_file, 'w') as f:
            f.write(config)
        if networks <= 10000:
            boot_delay = 25
        else:
            boot_delay = 75
        cord_test_quagga_restart(config_file = guest_config_file, boot_delay = boot_delay)

    @classmethod
    def zgenerate_vrouter_conf(cls, networks = 4):
        num = 0
        start_network = ( 11 << 24) | ( 0 << 16) | ( 0 << 8) | 0
        end_network =   ( 200 << 24 ) | ( 0 << 16)  | (0 << 8) | 0
        ports_dict = { 'ports' : {} }
        interface_list = []
        for n in xrange(start_network, end_network):
            if n & 255 == 0:
                port_map = ports_dict['ports']
                port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
                device_port_key = '{0}/{1}'.format(cls.device_id, port)
                try:
                    interfaces = port_map[device_port_key]['interfaces']
                except:
                    port_map[device_port_key] = { 'interfaces' : [] }
                    interfaces = port_map[device_port_key]['interfaces']
                    
                ips = '%d.%d.%d.2/24'%( (n >> 24) & 0xff, ( ( n >> 16) & 0xff ), ( (n >> 8 ) & 0xff ) )
                if num < cls.MAX_PORTS - 1:
                    interface_dict = { 'name' : 'b1-{}'.format(port), 'ips': [ips], 'mac' : '00:00:00:00:00:01' }
                    interfaces.append(interface_dict)
                    interface_list.append(interface_dict['name'])
                else:
                    interfaces[0]['ips'].append(ips)
                num += 1
                if num == networks:
                    break
        quagga_dict = { 'apps': { 'org.onosproject.router' : { 'router' : {} } } }
        quagga_router_dict = quagga_dict['apps']['org.onosproject.router']['router']
        quagga_router_dict['ospfEnabled'] = True
        quagga_router_dict['interfaces'] = interface_list
        quagga_router_dict['controlPlaneConnectPoint'] = '{0}/{1}'.format(cls.device_id, 
                                                                          networks + 1 if networks < cls.MAX_PORTS else cls.MAX_PORTS )
        return (cls.vrouter_device_dict, ports_dict, quagga_dict)

    @classmethod
    def generate_vrouter_conf(cls, networks = 4, peers = 1):
        num = 0
        start_peer = ( 192 << 24) | ( 168 << 16)  |  (10 << 8) | 0
        end_peer =   ( 200 << 24 ) | (168 << 16)  |  (10 << 8) | 0
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
    def generate_conf(cls, networks = 4):
        num = 0
        start_network = ( 11 << 24) | ( 10 << 16) | ( 10 << 8) | 0
        end_network =   ( 172 << 24 ) | ( 0 << 16)  | (0 << 8) | 0
        net_list = []
        peer_list = cls.peer_list
        network_list = []
        for n in xrange(start_network, end_network, 256):
            net = '%d.%d.%d.0'%( (n >> 24) & 0xff, ( ( n >> 16) & 0xff ), ( (n >> 8 ) & 0xff ) )
            network_list.append(net)
            gateway = peer_list[num % len(peer_list)][0]
            net_route = 'ip route {0}/24 {1}'.format(net, gateway)
            net_list.append(net_route)
            num += 1
            if num == networks:
                break
        cls.network_list = network_list
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
    def vrouter_configure(cls, networks = 4, peers = 1):
        ##Deactivate vrouter
        vrouter_configs = cls.vrouter_config_get(networks = networks, peers = peers)
        cls.start_onos(network_cfg = vrouter_configs)
        cls.vrouter_host_load()
        ##Start quagga
        cls.start_quagga(networks = networks)
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

    def vrouter_traffic_verify(self, positive_test = True):
        peers = len(self.peer_list)
        egress = peers + 1
        num = 0
        num_hosts = 5 if positive_test else 1
        for network in self.network_list:
            num_ips = num_hosts
            octets = network.split('.')
            for i in xrange(num_ips):
                octets[-1] = str(int(octets[-1]) + 1)
                dst_ip = '.'.join(octets)
                dst_mac = self.peer_list[ num % peers ] [1]
                port = (num % peers)
                ingress = port + 1
                #Since peers are on the same network
                ##Verify if flows are setup by sending traffic across
                self.vrouter_port_send_recv(ingress, egress, dst_mac, dst_ip, positive_test = positive_test)
            num += 1
    
    def __vrouter_network_verify(self, networks, peers = 1, positive_test = True):
        _, ports_map, egress_map = self.vrouter_configure(networks = networks, peers = peers)
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        ##We read from cli if we expect less number of routes to avoid cli timeouts
        if networks <= 10000:
            routes = json.loads(self.cli.routes(jsonFormat = True))
            #log.info('Routes: %s' %routes)
            assert_equal(len(routes['routes4']), networks)
            flows = json.loads(self.cli.flows(jsonFormat = True))
            flows = filter(lambda f: f['flows'], flows)
            #log.info('Flows: %s' %flows)
            assert_not_equal(len(flows), 0)
        self.vrouter_traffic_verify()
        if positive_test is False:
            self.__vrouter_network_verify_negative(networks, peers = peers)
        self.cliExit()
        self.vrouter_host_unload()
        return True

    def __vrouter_network_verify_negative(self, networks, peers = 1):
        ##Stop quagga. Test traffic again to see if flows were removed
        log.info('Stopping Quagga container')
        quaggaStop = QuaggaStopWrapper()
        time.sleep(2)
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

    def test_vrouter_1(self):
        '''Test vrouter with 5 routes'''
        res = self.__vrouter_network_verify(5, peers = 1)
        assert_equal(res, True)

    def test_vrouter_2(self):
        '''Test vrouter with 5 routes with 2 peers'''
        res = self.__vrouter_network_verify(5, peers = 2)
        assert_equal(res, True)

    def test_vrouter_3(self):
        '''Test vrouter with 6 routes with 3 peers'''
        res = self.__vrouter_network_verify(6, peers = 3)
        assert_equal(res, True)

    def test_vrouter_4(self):
        '''Test vrouter with 50 routes'''
        res = self.__vrouter_network_verify(50, peers = 1)
        assert_equal(res, True)

    def test_vrouter_5(self):
        '''Test vrouter with 50 routes and 5 peers'''
        res = self.__vrouter_network_verify(50, peers = 5)
        assert_equal(res, True)

    def test_vrouter_6(self):
        '''Test vrouter with 100 routes'''
        res = self.__vrouter_network_verify(100, peers = 1)
        assert_equal(res, True)

    def test_vrouter_7(self):
        '''Test vrouter with 100 routes and 10 peers'''
        res = self.__vrouter_network_verify(100, peers = 10)
        assert_equal(res, True)

    def test_vrouter_8(self):
        '''Test vrouter with 300 routes'''
        res = self.__vrouter_network_verify(300, peers = 1)
        assert_equal(res, True)

    def test_vrouter_9(self):
        '''Test vrouter with 1000 routes'''
        res = self.__vrouter_network_verify(1000, peers = 1)
        assert_equal(res, True)
    
    def test_vrouter_10(self):
        '''Test vrouter with 10000 routes'''
        res = self.__vrouter_network_verify(10000, peers = 1)
        assert_equal(res, True)
    
    @nottest
    def test_vrouter_11(self):
        '''Test vrouter with 100000 routes'''
        res = self.__vrouter_network_verify(100000, peers = 1)
        assert_equal(res, True)

    @nottest
    def test_vrouter_12(self):
        '''Test vrouter with 1000000 routes'''
        res = self.__vrouter_network_verify(1000000, peers = 1)
        assert_equal(res, True)

    def test_vrouter_13(self):
        '''Test vrouter by installing 5 routes, removing Quagga and re-starting Quagga back'''
        res = self.__vrouter_network_verify(5, peers = 1, positive_test = False)

    def test_vrouter_14(self):
        '''Test vrouter by installing 50 routes, removing Quagga and re-starting Quagga back'''
        res = self.__vrouter_network_verify(50, peers = 1, positive_test = False)
