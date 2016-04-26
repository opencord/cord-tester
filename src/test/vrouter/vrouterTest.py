import unittest
from nose.tools import *
from scapy.all import *
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnosFlowCtrl import OnosFlowCtrl, get_mac
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos
from CordTestServer import cord_test_onos_restart
from portmaps import g_subscriber_port_map
import threading
import time
import os
import json
log.setLevel('INFO')

class Quagga(Container):
    quagga_config = '/root/config'
    def __init__(self, name = 'cord-quagga', image = 'cord-test/quagga', tag = 'latest'):
        super(Quagga, self).__init__(name, image, tag = tag)
        if not self.exists():
            raise Exception('Quagga container was not started by cord-test')
        
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
debug zebra rib
debug zebra kernel
debug zebra fpm
!
!interface eth1
! ip address 10.10.0.3/16
line vty
 exec-timeout 0 0
'''
    test_path = os.path.dirname(os.path.realpath(__file__))
    quagga_config_path = os.path.join(test_path, '..', 'setup/quagga-config')
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '172.17.0.50'
    MAX_PORTS = 100

    @classmethod
    def setUpClass(cls):
        ''' Activate the vrouter apps'''
        cls.olt = OltConfig()
        cls.port_map = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        cls.vrouter_host_load(host = cls.GATEWAY)
        time.sleep(3)
        
    @classmethod
    def tearDownClass(cls):
        '''Deactivate the vrouter apps'''
        cls.vrouter_host_unload()

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
    def vrouter_config_get(cls, networks = 4):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks)
        return vrouter_configs
        ##ONOS router does not support dynamic reconfigurations
        #for config in vrouter_configs:
        #    cls.onos_load_config(config)
        #    time.sleep(5)

    @classmethod
    def vrouter_host_load(cls, host=GATEWAY, iface = 'veth0'):
        config_cmds = ( 'ifconfig {0} {1}'.format(iface, host),
                        'arping -I {0} {1} -c 2'.format(iface, host),
                        )
        for cmd in config_cmds:
            os.system(cmd)

    @classmethod
    def vrouter_host_unload(cls, iface='veth0'):
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
    def start_quagga(cls, stop = True, networks = 4, gateway = GATEWAY):
        quagga = Quagga()
        log.info('Starting Quagga on container %s with %d networks' %(quagga.name, networks))
        if stop is True:
            quagga.execute('{}/stop.sh'.format(Quagga.quagga_config))
        config = cls.generate_conf(networks = networks, gateway = gateway)
        with open('{}/testrib_gen.conf'.format(cls.quagga_config_path), 'w') as f:
            f.write(config)
        quagga.execute('{0}/start.sh {1}/testrib_gen.conf'.format(Quagga.quagga_config, Quagga.quagga_config))
        time.sleep(10)

    @classmethod
    def generate_vrouter_conf(cls, networks = 4):
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
    def generate_conf(cls, networks = 4, gateway = GATEWAY):
        num = 0
        start_network = ( 11 << 24) | ( 0 << 16) | ( 0 << 8) | 0
        end_network =   ( 200 << 24 ) | ( 0 << 16)  | (0 << 8) | 0
        net_list = []
        for n in xrange(start_network, end_network):
            if n & 255 == 0:
                net = '%d.%d.%d.0'%( (n >> 24) & 0xff, ( ( n >> 16) & 0xff ), ( (n >> 8 ) & 0xff ) )
                net_route = 'ip route {0}/24 {1}'.format(net, gateway)
                net_list.append(net_route)
                num += 1
            if num == networks:
                break
        zebra_routes = '\n'.join(net_list)
        log.info('Zebra routes: \n:%s\n' %cls.zebra_conf + zebra_routes)
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
    def vrouter_configure(cls, networks = 4):
        ##Deactivate vrouter
        vrouter_configs = cls.vrouter_config_get(networks = networks)
        #cls.start_onos(network_cfg = vrouter_configs)
        ##Start quagga with 4 networks
        #cls.start_quagga(networks = networks, stop = True, gateway = cls.GATEWAY)
        return vrouter_configs
    
    def vrouter_port_send_recv(self, ingress, egress, dst_mac, dst_ip):
        src_mac = '00:00:00:00:00:02'
        src_ip = '172.17.0.100'
        self.success = False
        def recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True
            sniff(count=2, timeout=5, 
                  lfilter = lambda p: IP in p and p[IP].dst == dst_ip and p[IP].src == src_ip,
                  prn = recv_cb, iface = self.port_map[egress])

        t = threading.Thread(target = recv_task)
        t.start()
        L2 = Ether(src = src_mac, dst = dst_mac)
        L3 = IP(src = src_ip, dst = dst_ip)
        pkt = L2/L3
        log.info('Sending a packet with dst ip %s, dst mac %s on port %s to verify if flows are correct' %
                 (dst_ip, dst_mac, self.port_map[ingress]))
        sendp(pkt, count=50, iface = self.port_map[ingress])
        t.join()
        assert_equal(self.success, True)

    def vrouter_traffic_verify(self, ports_dict, egress_dict):
        egress = int(egress_dict['apps']['org.onosproject.router']['router']['controlPlaneConnectPoint'].split('/')[1])
        for dev in ports_dict['ports'].keys():
            for intf in ports_dict['ports'][dev]['interfaces']:
                for ip in intf['ips']:
                    dst_ip = ip.split('/')[0]
                    dst_mac = intf['mac']
                    port = intf['name']
                    ingress = int(port.split('-')[1])
                    ##Verify if flows are setup by sending traffic across
                    self.vrouter_port_send_recv(ingress, egress, dst_mac, dst_ip)

    def __vrouter_network_verify(self, networks):
        _, ports_map, egress_map = self.vrouter_configure(networks = networks)
        self.cliEnter()
        ##Now verify
        hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %hosts)
        routes = json.loads(self.cli.routes(jsonFormat = True))
        log.info('Routes: %s' %routes)
        #assert_equal(len(routes['routes4']), networks)
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        #log.info('Flows: %s' %flows)
        assert_not_equal(len(flows), 0)
        self.vrouter_traffic_verify(ports_map, egress_map)
        self.cliExit()
        return True

    def test_vrouter_1(self):
        '''Test vrouter with 5 routes'''
        res = self.__vrouter_network_verify(5)
        assert_equal(res, True)

    def test_vrouter_2(self):
        '''Test vrouter with 20 routes'''
        res = self.__vrouter_network_verify(50)
        assert_equal(res, True)

    def test_vrouter_3(self):
        '''Test vrouter with 100 routes'''
        res = self.__vrouter_network_verify(100)
        assert_equal(res, True)

    def test_vrouter_4(self):
        '''Test vrouter with 200 routes'''
        res = self.__vrouter_network_verify(300)
        assert_equal(res, True)
