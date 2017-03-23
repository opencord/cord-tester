import unittest
from twisted.internet import defer
from nose.tools import *
from IGMP import *
from ACL import ACLTest
from DHCP import DHCPTest
from Channels import Channels, IgmpChannel
from subscriberDb import SubscriberDB
import time, monotonic
from CordTestUtils import get_mac
from OltConfig import OltConfig
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl
from CordContainer import Container, Onos, Quagga
from onosclidriver import OnosCliDriver
from CordTestServer import CordTestServer, cord_test_onos_restart, cord_test_quagga_restart,cord_test_quagga_stop, cord_test_quagga_shell,cord_test_shell
from portmaps import g_subscriber_port_map
import time, monotonic
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *
import os
import json
from socket import socket
import pexpect
from Stats import Stats
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from OnosFlowCtrl import OnosFlowCtrl
from nose.twistedtools import reactor, deferred
import tempfile
import threading
from threading import current_thread
from threadPool import ThreadPool
import random
import collections
import requests
log.setLevel('INFO')
class cluster_igmp(object):
    V_INF1 = 'veth0'
    V_INF2 = 'veth1'
    MGROUP1 = '239.1.2.3'
    MGROUP2 = '239.2.2.3'
    MINVALIDGROUP1 = '255.255.255.255'
    MINVALIDGROUP2 = '239.255.255.255'
    MMACGROUP1 = "01:00:5e:01:02:03"
    MMACGROUP2 = "01:00:5e:02:02:03"
    IGMP_DST_MAC = "01:00:5e:00:00:16"
    IGMP_SRC_MAC = "5a:e1:ac:ec:4d:a1"
    IP_SRC = '1.2.3.4'
    IP_DST = '224.0.0.22'
    NEGATIVE_TRAFFIC_STATUS = 1
    igmp_eth = Ether(dst = IGMP_DST_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST)
    IGMP_TEST_TIMEOUT = 5
    IGMP_QUERY_TIMEOUT = 60
    MCAST_TRAFFIC_TIMEOUT = 10
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    app = 'org.opencord.igmp'
    olt_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json')
    ROVER_TEST_TIMEOUT = 300 #3600*86
    ROVER_TIMEOUT = (ROVER_TEST_TIMEOUT - 100)
    ROVER_JOIN_TIMEOUT = 60

    @classmethod
    def setUpClass(cls,controller=None):
          cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
          cls.port_map, _ = cls.olt.olt_port_map()
          OnosCtrl.cord_olt_config(cls.olt, controller=controller)

    @classmethod
    def tearDownClass(cls): pass

    def setUp(self,controller=None):
	self.setUpClass(controller=controller)
	self.get_igmp_intf()
        ''' Activate the igmp app'''
        self.onos_ctrl = OnosCtrl(self.app,controller=controller)
        self.onos_ctrl.activate()
        self.igmp_channel = IgmpChannel(controller=controller)

    def tearDown(self): pass

    def onos_load_config(self, config,controller=None):
        log.info('onos load config is %s'%config)
        status, code = OnosCtrl(self.app).config(config,controller=controller)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    def onos_ssm_table_load(self, groups, src_list = ['1.2.3.4'],controller=None,flag = False):
          ssm_dict = {'apps' : { 'org.onosproject.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.onosproject.igmp']['ssmTranslate']
          if flag: #to maintain seperate group-source pair.
              for i in range(len(groups)):
                  d = {}
                  d['source'] = src_list[i] or '0.0.0.0'
                  d['group'] = groups[i]
                  ssm_xlate_list.append(d)
          else:
              for g in groups:
                  for s in src_list:
                      d = {}
                      d['source'] = s or '0.0.0.0'
                      d['group'] = g
                      ssm_xlate_list.append(d)
          self.onos_load_config(ssm_dict,controller=controller)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          self.igmp_channel.cord_port_table_load(cord_port_map)
          time.sleep(2)

    def mcast_ip_range(self,start_ip = '224.0.1.0', end_ip = '224.0.1.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range

    def random_mcast_ip(self,start_ip = '224.0.1.0', end_ip = '224.0.1.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return random.choice(ip_range)

    def source_ip_range(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range
    def iptomac(self, mcast_ip):
        mcast_mac =  '01:00:5e:'
        octets = mcast_ip.split('.')
        second_oct = int(octets[1]) & 127
        third_oct = int(octets[2])
        fourth_oct = int(octets[3])
        mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
        return mcast_mac

    def randomsourceip(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return random.choice(ip_range)

    def get_igmp_intf(self):
        inst = os.getenv('TEST_INSTANCE', None)
        if not inst:
            return 'veth0'
        inst = int(inst) + 1
        if inst >= self.port_map['uplink']:
            inst += 1
        if self.port_map.has_key(inst):
              return self.port_map[inst]
        return 'veth0'

    def igmp_verify_join(self, igmpStateList):
        sendState, recvState = igmpStateList
        ## check if the send is received for the groups
        for g in sendState.groups:
            tx_stats = sendState.group_map[g][0]
            tx = tx_stats.count
            assert_greater(tx, 0)
            rx_stats = recvState.group_map[g][1]
            rx = rx_stats.count
            assert_greater(rx, 0)
            log.info('Receive stats %s for group %s' %(rx_stats, g))

        log.info('IGMP test verification success')

    def igmp_verify_leave(self, igmpStateList, leave_groups):
        sendState, recvState = igmpStateList[0], igmpStateList[1]
        ## check if the send is received for the groups
        for g in sendState.groups:
            tx_stats = sendState.group_map[g][0]
            rx_stats = recvState.group_map[g][1]
            tx = tx_stats.count
            rx = rx_stats.count
            assert_greater(tx, 0)
            if g not in leave_groups:
                log.info('Received %d packets for group %s' %(rx, g))
        for g in leave_groups:
            rx = recvState.group_map[g][1].count
            assert_equal(rx, 0)

        log.info('IGMP test verification success')

    def mcast_traffic_timer(self):
          self.mcastTraffic.stopReceives()

    def send_mcast_cb(self, send_state):
        for g in send_state.groups:
            send_state.update(g, tx = 1)
        return 0

    ##Runs in the context of twisted reactor thread
    def igmp_recv(self, igmpState, iface = 'veth0'):
        p = self.recv_socket.recv()
        try:
              send_time = float(p.payload.load)
              recv_time = monotonic.monotonic()
        except:
              log.info('Unexpected Payload received: %s' %p.payload.load)
              return 0
        #log.info( 'Recv in %.6f secs' %(recv_time - send_time))
        igmpState.update(p.dst, rx = 1, t = recv_time - send_time)
        return 0

    def send_igmp_join(self, groups, src_list = ['1.2.3.4'], record_type=IGMP_V3_GR_TYPE_INCLUDE,
                       ip_pkt = None, iface = 'veth0', ssm_load = False, delay = 1):
        if ssm_load is True:
              self.onos_ssm_table_load(groups, src_list)
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype= record_type, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        sendp(pkt, iface=iface)
        log.info('igmp join packet is %s'%pkt.show())
        if delay != 0:
            time.sleep(delay)

class cluster_tls():
    eap_app = 'org.opencord.aaa'
    CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIEyTCCA7GgAwIBAgIJAM6l2jUG56pLMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UE
ChMKQ2llbmEgSW5jLjEeMBwGCSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYw
JAYDVQQDEx1FeGFtcGxlIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNjAzMTEx
ODUzMzVaFw0xNzAzMDYxODUzMzVaMIGLMQswCQYDVQQGEwJVUzELMAkGA1UECBMC
Q0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UEChMKQ2llbmEgSW5jLjEeMBwG
CSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYwJAYDVQQDEx1FeGFtcGxlIENl
cnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL9Jv54TkqycL3U2Fdd/y5NXdnPVXwAVV3m6I3eIffVCv8eS+mwlbl9dnbjo
qqlGEgA3sEg5HtnKoW81l3PSyV/YaqzUzbcpDlgWlbNkFQ3nVxh61gSU34Fc4h/W
plSvCkwGSbV5udLtEe6S9IflP2Fu/eXa9vmUtoPqDk66p9U/nWVf2H1GJy7XanWg
wke+HpQvbzoSfPJS0e5Rm9KErrzaIkJpqt7soW+OjVJitUax7h45RYY1HHHlbMQ0
ndWW8UDsCxFQO6d7nsijCzY69Y8HarH4mbVtqhg3KJevxD9UMRy6gdtPMDZLah1c
LHRu14ucOK4aF8oICOgtcD06auUCAwEAAaOCASwwggEoMB0GA1UdDgQWBBQwEs0m
c8HARTVp21wtiwgav5biqjCBwAYDVR0jBIG4MIG1gBQwEs0mc8HARTVp21wtiwga
v5biqqGBkaSBjjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQH
EwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5hIEluYy4xHjAcBgkqhkiG9w0BCQEW
D2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBB
dXRob3JpdHmCCQDOpdo1BueqSzAMBgNVHRMEBTADAQH/MDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5jb20vZXhhbXBsZV9jYS5jcmwwDQYJKoZI
hvcNAQELBQADggEBAK+fyAFO8CbH35P5mOX+5wf7+AeC+5pwaFcoCV0zlfwniANp
jISgcIX9rcetLxeYRAO5com3+qLdd9dGVNL0kwufH4QhlSPErG7OLHHAs4JWVhUo
bH3lK9lgFVlnCDBtQhslzqScR64SCicWcQEjv3ZMZsJwYLvl8unSaKz4+LVPeJ2L
opCpmZw/V/S2NhBbe3QjTiRPmDev2gbaO4GCfi/6sCDU7UO3o8KryrkeeMIiFIej
gfwn9fovmpeqCEyupy2JNNUTJibEuFknwx7JAX+htPL27nEgwV1FYtwI3qLiZqkM
729wo9cFSslJNZBu+GsBP5LszQSuvNTDWytV+qY=
-----END CERTIFICATE-----'''
    def __init__(self):
	pass
    def setUp(self,controller=None):
        self.onos_ctrl = OnosCtrl(self.eap_app,controller=controller)
        self.onos_aaa_config(controller=controller)

    def onos_aaa_config(self,controller=None):
	log.info('controller in onos_aaa_config is %s'%controller)
        aaa_dict = {'apps' : { 'org.opencord.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                'radiusIp': '172.17.0.2' } } } }
        radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
        aaa_dict['apps']['org.opencord.aaa']['AAA']['radiusIp'] = radius_ip
        self.onos_ctrl.activate()
        time.sleep(2)
        self.onos_load_config(aaa_dict,controller=controller)

    def onos_load_config(self, config,controller=None):
	log.info('controller in onos_load_config is %s'%controller)
        log.info('onos load config is %s'%config)
        status, code = OnosCtrl(self.eap_app).config(config,controller=controller)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)


class cluster_flows():

    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    default_port_map = {
        PORT_TX_DEFAULT : INTF_TX_DEFAULT,
        PORT_RX_DEFAULT : INTF_RX_DEFAULT,
        INTF_TX_DEFAULT : PORT_TX_DEFAULT,
        INTF_RX_DEFAULT : PORT_RX_DEFAULT
        }
    app = 'org.onosproject.cli'

    def incmac(self, mac):
        tmp =  str(hex(int('0x'+mac,16)+1).split('x')[1])
        mac = '0'+ tmp if len(tmp) < 2 else tmp
        return mac

    def next_mac(self, mac):
        mac = mac.split(":")
        mac[5] = self.incmac(mac[5])

        if len(mac[5]) > 2:
           mac[0] = self.incmac(mac[0])
           mac[5] = '01'

        if len(mac[0]) > 2:
           mac[0] = '01'
           mac[1] = self.incmac(mac[1])
           mac[5] = '01'
        return ':'.join(mac)

    def to_egress_mac(cls, mac):
        mac = mac.split(":")
        mac[4] = '01'

        return ':'.join(mac)

    def inc_ip(self, ip, i):

        ip[i] =str(int(ip[i])+1)
        return '.'.join(ip)


    def next_ip(self, ip):

        lst = ip.split('.')
        for i in (3,0,-1):
            if int(lst[i]) < 255:
               return self.inc_ip(lst, i)
            elif int(lst[i]) == 255:
               lst[i] = '0'
               if int(lst[i-1]) < 255:
                  return self.inc_ip(lst,i-1)
               elif int(lst[i-2]) < 255:
                  lst[i-1] = '0'
                  return self.inc_ip(lst,i-2)
               else:
                  break

    def randomip(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return random.choice(ip_range)

    def ip_range(self,start_ip = '10.10.0.1', end_ip = '10.10.0.100'):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        temp = start
        ip_range = []
        ip_range.append(start_ip)
        while temp != end:
            start[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 255:
                    temp[i] = 0
                    temp[i-1] += 1
            ip_range.append(".".join(map(str, temp)))
        return ip_range

    def to_egress_ip(self, ip):
        lst=ip.split('.')
        lst[0] = '182'
        return '.'.join(lst)

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = cls.default_port_map
        cls.device_id = OnosCtrl.get_device_id()

class cluster_proxyarp():
    #apps = ('org.onosproject.vrouter','org.onosproject.proxyarp')
    app = 'org.onosproject.proxyarp'
    device_id = 'of:' + get_mac()
    device_dict = { "devices" : {
                "{}".format(device_id) : {
                    "basic" : {
                        "driver" : "softrouter"
                    }
                }
             },
          }
    test_path = os.path.dirname(os.path.realpath(__file__))
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '192.168.10.50'
    INGRESS_PORT = 1
    EGRESS_PORT = 2
    MAX_PORTS = 100
    hosts_list = [ ('192.168.10.1', '00:00:00:00:00:01'), ('192.168.11.1', '00:00:00:00:02:01'), ]

    olt_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json')

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
	print('port map in proxyarp setUpClass is %s'%cls.port_map)
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        time.sleep(3)
        cls.load_device_id()

    @classmethod
    def load_device_id(cls):
        did = OnosCtrl.get_device_id()
        cls.device_id = did
        cls.device_dict = { "devices" : {
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
    def interface_config_load(cls, interface_cfg = None):
        if type(interface_cfg) is tuple:
            res = []
            for v in interface_cfg:
                if type(v) == list:
                    pass
                else:
                    res += v.items()
                    config = dict(res)
        else:
            config = interface_cfg
        cfg = json.dumps(config)
        #with open('{}/network-cfg.json'.format(cls.onos_config_path), 'w') as f:
        #    f.write(cfg)
        #return cord_test_onos_restart(config=config)

    @classmethod
    def host_config_load(cls, host_config = None, controller=None):
        for host in host_config:
            status, code = OnosCtrl(cls.app).host_config(host,onos_ip=controller)
            if status is False:
                log.info('JSON request returned status %d' %code)
                assert_equal(status, True)

    @classmethod
    def generate_interface_config(cls, hosts = 1):
        num = 0
        start_host = ( 192 << 24) | ( 168 << 16)  |  (10 << 8) | 0
        end_host =   ( 200 << 24 ) | (168 << 16)  |  (10 << 8) | 0
        ports_dict = { 'ports' : {} }
        interface_list = []
        hosts_list = []
        for n in xrange(start_host, end_host, 256):
            port_map = ports_dict['ports']
            port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            device_port_key = '{0}/{1}'.format(cls.device_id, port)
            try:
                interfaces = port_map[device_port_key]['interfaces']
            except:
                port_map[device_port_key] = { 'interfaces' : [] }
                interfaces = port_map[device_port_key]['interfaces']
            ip = n + 1
            host_ip = n + 2
            ips = '%d.%d.%d.%d/24'%( (ip >> 24) & 0xff, ( (ip >> 16) & 0xff ), ( (ip >> 8 ) & 0xff ), ip & 0xff)
            host = '%d.%d.%d.%d' % ( (host_ip >> 24) & 0xff, ( ( host_ip >> 16) & 0xff ), ( (host_ip >> 8 ) & 0xff ), host_ip & 0xff )
            mac = RandMAC()._fix()
            hosts_list.append((host, mac))
            if num < cls.MAX_PORTS - 1:
                interface_dict = { 'name' : 'b1-{}'.format(port), 'ips': [ips], 'mac' : mac }
                interfaces.append(interface_dict)
                interface_list.append(interface_dict['name'])
            else:
                interfaces[0]['ips'].append(ips)
            num += 1
            if num == hosts:
                break
        cls.hosts_list = hosts_list
        return (cls.device_dict, ports_dict, hosts_list)

    @classmethod
    def generate_host_config(cls):
        num = 0
        hosts_dict = {}
        for host, mac in cls.hosts_list:
            port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            hosts_dict[host] = {'mac':mac, 'vlan':'none', 'ipAddresses':[host], 'location':{ 'elementId' : '{}'.format(cls.device_id), 'port': port}}
            num += 1
        return hosts_dict.values()

    @classmethod
    def proxyarp_activate(cls, deactivate = False,controller=None):
        app = 'org.onosproject.proxyarp'
        onos_ctrl = OnosCtrl(app,controller=controller)
        if deactivate is True:
            onos_ctrl.deactivate()
        else:
            onos_ctrl.activate()
        time.sleep(3)

    @classmethod
    def proxyarp_config(cls, hosts = 1,controller=None):
        proxyarp_configs = cls.generate_interface_config(hosts = hosts)
        cls.interface_config_load(interface_cfg = proxyarp_configs)
        hostcfg = cls.generate_host_config()
        cls.host_config_load(host_config = hostcfg,controller=controller)
        return proxyarp_configs

    def proxyarp_arpreply_verify(self, ingress, hostip, hostmac, PositiveTest=True):
        #log.info('verifying arp reply for host ip %s host mac %s on interface %s'%(hostip ,hostmac ,self.port_map[ingress]))
        self.success = False
        def recv_task():
            def recv_cb(pkt):
                log.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                self.success = True if PositiveTest == True else False
            sniff(count=1, timeout=2, lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].hwsrc == hostmac,
                  prn = recv_cb, iface = self.port_map[ingress])
        t = threading.Thread(target = recv_task)
        t.start()
        pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst=hostip))
        log.info('sending arp request  for dest ip %s on interface %s' %
                 (hostip, self.port_map[ingress]))
        sendp( pkt, count = 10, iface = self.port_map[ingress])
        t.join()
        if PositiveTest:
            assert_equal(self.success, True)
        else:
            assert_equal(self.success, False)

    def proxyarp_hosts_verify(self, hosts = 1,PositiveTest = True):
	log.info('verifying arp reply for host ip host mac on interface %s'%(self.port_map[2]))
        _,_,hosts_config = self.proxyarp_config(hosts = hosts)
        log.info('\nhosts_config %s and its type %s'%(hosts_config,type(hosts_config)))
        self.cliEnter()
        connected_hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log.info('Discovered hosts: %s' %connected_hosts)
        #We read from cli if we expect less number of routes to avoid cli timeouts
        if hosts <= 10000:
            assert_equal(len(connected_hosts), hosts)
        ingress = hosts+1
        for hostip, hostmac in hosts_config:
                self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = PositiveTest)
                time.sleep(1)
        self.cliExit()
        return True

class cluster_vrouter(object):
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
	#cls.vrouter_activate(cls, deactivate = True)


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

    def cliEnter(self,controller=None):
        retries = 0
        while retries < 3:
            self.cli = OnosCliDriver(connect = True,controller=controller)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

    @classmethod
    def onos_load_config(cls, config,controller=None):
        status, code = OnosCtrl.config(config,controller=controller)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    @classmethod
    def vrouter_config_get(cls, networks = 4, peers = 1, peer_address = None,
                           route_update = None, router_address = None):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks, peers = peers,
                                                    peer_address = peer_address, router_address = router_address)
        return vrouter_configs

    @classmethod
    def vrouter_host_load(cls,peer_address = None,controller=None):
        index = 1
        hosts_dict = {}
	peer_info = peer_address if peer_address is not None else cls.peer_list
        for host,_ in peer_info:
	    #iface = cls.port_map[index]
	    mac = RandMAC()._fix()
            #port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
	    log.info('creating host with ip %s and mac %s'%(host,mac))
            hosts_dict[host] = {'mac':mac, 'vlan':'none', 'ipAddresses':[host], 'location':{ 'elementId' : '{}'.format(cls.device_id), 'port': index}}
	    index += 1
	for host in hosts_dict.values():
            status, code = OnosCtrl.host_config(host,onos_ip=controller)
            if status is False:
                log.info('JSON request returned status %d' %code)
                return False
        return True

    """@classmethod
    def vrouter_host_load(cls, peer_address = None):
	#cls.setUpClass()
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
    """
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
	cfg = json.dumps(config)
        log.info('Restarting ONOS with new network configuration %s'%config)
        #return cord_test_onos_restart(config = config)
	with open('{}/network-cfg.json'.format(cls.onos_config_path), 'w') as f:
            f.write(cfg)
        return cord_test_onos_restart(config=config)

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
    def vrouter_activate(cls, deactivate = False,controller=None):
        app = 'org.onosproject.vrouter'
        onos_ctrl = OnosCtrl(app,controller=controller)
        if deactivate is True:
            onos_ctrl.deactivate()
        else:
            onos_ctrl.activate()
        time.sleep(3)

    @classmethod
    def vrouter_configure(cls, networks = 4, peers = 1, peer_address = None,
                          route_update = None, router_address = None, time_expire = None, adding_new_routes = None,controller=None):
        vrouter_configs = cls.vrouter_config_get(networks = networks, peers = peers,
                                                 peer_address = peer_address, route_update = route_update)
        cls.start_onos(network_cfg = vrouter_configs)
        cls.vrouter_host_load(controller=controller)
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

    def vrouter_network_verify(self, networks, peers = 1, positive_test = True,
                                 start_network = None, start_peer_address = None, route_update = None,
                                 invalid_peers = None, time_expire = None, unreachable_route_traffic = None,
                                 deactivate_activate_vrouter = None, adding_new_routes = None,controller=None):

        _, ports_map, egress_map = self.vrouter_configure(networks = networks, peers = peers,
                                                          peer_address = start_peer_address,
                                                          route_update = route_update,
                                                          router_address = start_network,
                                                          time_expire = time_expire,
                                                          adding_new_routes = adding_new_routes,
							  controller=controller)
        self.cliEnter(controller=controller)
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
            self.vrouter_network_verify_negative(networks, peers = peers)
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
	return True

    def vrouter_network_verify_negative(self, networks, peers = 1):
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

class cluster_acl(object):
    app = 'org.onosproject.acl'
    device_id = 'of:' + get_mac('ovsbr0')
    test_path = os.path.dirname(os.path.realpath(__file__))
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    GATEWAY = '192.168.10.50'
    INGRESS_PORT = 1
    EGRESS_PORT = 2
    ingress_iface = 1
    egress_iface = 2
    MAX_PORTS = 100
    CURRENT_PORT_NUM = egress_iface
    ACL_SRC_IP = '192.168.20.3/32'
    ACL_DST_IP = '192.168.30.2/32'
    ACL_SRC_IP_RULE_2 = '192.168.40.3/32'
    ACL_DST_IP_RULE_2 = '192.168.50.2/32'
    ACL_SRC_IP_PREFIX_24 = '192.168.20.3/24'
    ACL_DST_IP_PREFIX_24 = '192.168.30.2/24'
    HOST_DST_IP = '192.168.30.0/24'
    HOST_DST_IP_RULE_2 = '192.168.50.0/24'

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map,_ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        time.sleep(3)
        log.info('port_map = %s'%cls.port_map[1] )

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the acl app'''
    def setUp(self,controller=None):
	self.setUpClass()
        ''' Activate the acl app'''
        self.maxDiff = None ##for assert_equal compare outputs on failure
        self.onos_ctrl = OnosCtrl(self.app,controller=controller)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(1)
        #status, _ = ACLTest.remove_acl_rule()
        #log.info('Start setup')
        #assert_equal(status, True)

    def tearDown(self):
        '''Deactivate the acl app'''
        log.info('Tear down setup')
        self.CURRENT_PORT_NUM = 4

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
    def acl_hosts_add(cls, dstHostIpMac, egress_iface_count = 1,  egress_iface_num = None):
	cls.setUpClass()
        index = 0
        if egress_iface_num is None:
            egress_iface_num = cls.egress_iface
        for ip,_ in dstHostIpMac:
            egress = cls.port_map[egress_iface_num]
            log.info('Assigning ip %s to interface %s' %(ip, egress))
            config_cmds_egress = ( 'ifconfig {} 0'.format(egress),
                                   'ifconfig {0} up'.format(egress),
                                   'ifconfig {0} {1}'.format(egress, ip),
                                   'arping -I {0} {1} -c 2'.format(egress, ip.split('/')[0]),
                                   'ifconfig {0}'.format(egress),
                                 )
            for cmd in config_cmds_egress:
                os.system(cmd)
            index += 1
            if index == egress_iface_count:
               break
            egress_iface_count += 1
            egress_iface_num += 1


    @classmethod
    def acl_hosts_remove(cls, egress_iface_count = 1,  egress_iface_num = None):
	cls.setUpClass()
        if egress_iface_num is None:
           egress_iface_num = cls.egress_iface
        n = 0
        for n in range(egress_iface_count):
           egress = cls.port_map[egress_iface_num]
           config_cmds_egress = ('ifconfig {} 0'.format(egress))
           os.system(config_cmds_egress)
           egress_iface_num += 1

    def acl_rule_traffic_send_recv(self, srcMac, dstMac, srcIp, dstIp, ingress =None, egress=None, ip_proto=None, dstPortNum = None, positive_test = True):
	self.setUpClass()
        if ingress is None:
           ingress = self.ingress_iface
        if egress is None:
           egress = self.egress_iface
        ingress = self.port_map[ingress]
        egress = self.port_map[egress]
        self.success = False if positive_test else True
        timeout = 10 if positive_test else 1
        count = 2 if positive_test else 1
        self.start_sending = True
        def recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
                self.success = True if positive_test else False
            sniff(count=count, timeout=timeout,
                  lfilter = lambda p: IP in p and p[IP].dst == dstIp.split('/')[0] and p[IP].src == srcIp.split('/')[0],
                  prn = recv_cb, iface = egress)
            self.start_sending = False

        t = threading.Thread(target = recv_task)
        t.start()
        L2 = Ether(src = srcMac, dst = dstMac)
        L3 = IP(src = srcIp.split('/')[0], dst = dstIp.split('/')[0])
        pkt = L2/L3
        log.info('Sending a packet with dst ip %s, src ip %s , dst mac %s src mac %s on port %s to verify if flows are correct' %
                 (dstIp.split('/')[0], srcIp.split('/')[0], dstMac, srcMac, ingress))
        while self.start_sending is True:
            sendp(pkt, count=50, iface = ingress)
        t.join()
        assert_equal(self.success, True)

    @classmethod
    def onos_load_config(cls, config,controller=None):
        status, code = OnosCtrl.config(config,controller=controller)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

class cluster_dhcprelay(object):
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
    onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))

    @classmethod
    def setUpClass(cls,controller=None):
	log.info('controller ip in dhcp setup def is %s'%controller)
        ''' Activate the dhcprelay app'''
        OnosCtrl(cls.app_dhcp,controller=controller).deactivate()
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.app,controller=controller)
        status, _ = cls.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)
        cls.dhcp_relay_setup(controller=controller)
        ##start dhcpd initially with default config
        cls.dhcpd_start(controller=controller)

    @classmethod
    def tearDownClass(cls,controller=None):
        '''Deactivate the dhcp relay app'''
        try:
            os.unlink('{}/dhcpd.conf'.format(cls.dhcp_data_dir))
            os.unlink('{}/dhcpd.leases'.format(cls.dhcp_data_dir))
        except: pass
	OnosCtrl(cls.app,controller=controller).deactivate()
        #cls.onos_ctrl.deactivate()
        cls.dhcpd_stop()
        #cls.dhcp_relay_cleanup()

    @classmethod
    def dhcp_relay_setup(cls,controller=None):
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
            cls.onos_interface_load(interface_list,controller=controller)

    @classmethod
    def dhcp_relay_cleanup(cls):
        ##reset the ONOS port configuration back to default
        if cls.onos_restartable is True:
            log.info('Cleaning up dhcp relay config by restarting ONOS with default network cfg')
            return cord_test_onos_restart(config = {})

    @classmethod
    def onos_load_config(cls, config,controller=None):
	log.info('loading onos config in controller %s'%controller)
        status, code = OnosCtrl.config(config,controller=controller)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    @classmethod
    def onos_interface_load(cls, interface_list,controller=None):
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

        cls.onos_load_config(interface_dict,controller=controller)

    @classmethod
    def onos_dhcp_relay_load(cls, server_ip, server_mac,controller=None):
        relay_device_map = '{}/{}'.format(cls.relay_device_id, cls.relay_interface_port)
        dhcp_dict = {'apps':{'org.onosproject.dhcp-relay':{'dhcprelay':
                                                          {'dhcpserverConnectPoint':relay_device_map,
                                                           'serverip':server_ip,
                                                           'servermac':server_mac
                                                           }
                                                           }
                             }
                     }
        cls.onos_load_config(dhcp_dict,controller=controller)

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
                    subnet = default_subnet_config,controller=None):
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
        cls.onos_dhcp_relay_load(*intf_info[0],controller=controller)

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

class Subscriber(Channels):
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    STATS_RX = 0
    STATS_TX = 1
    STATS_JOIN = 2
    STATS_LEAVE = 3
    SUBSCRIBER_SERVICES = 'DHCP IGMP TLS'
    def __init__(self, name = 'sub', service = SUBSCRIBER_SERVICES, port_map = None,
        num = 1, channel_start = 0,
        tx_port = PORT_TX_DEFAULT, rx_port = PORT_RX_DEFAULT,
        iface = INTF_RX_DEFAULT, iface_mcast = INTF_TX_DEFAULT,
        mcast_cb = None, loginType = 'wireless'):
        self.tx_port = tx_port
        self.rx_port = rx_port
        self.port_map = port_map or g_subscriber_port_map
        try:
            self.tx_intf = self.port_map[tx_port]
            self.rx_intf = self.port_map[rx_port]
        except:
            self.tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            self.rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        log.info('Subscriber %s, rx interface %s, uplink interface %s' %(name, self.rx_intf, self.tx_intf))
        Channels.__init__(self, num, channel_start = channel_start,
                                   iface = self.rx_intf, iface_mcast = self.tx_intf, mcast_cb = mcast_cb)
        self.name = name
        self.service = service
        self.service_map = {}
        services = self.service.strip().split(' ')
        for s in services:
            self.service_map[s] = True
        self.loginType = loginType
        ##start streaming channels
        self.join_map = {}
        ##accumulated join recv stats
        self.join_rx_stats = Stats()
        self.recv_timeout = False

    def has_service(self, service):
        if self.service_map.has_key(service):
            return self.service_map[service]
        if self.service_map.has_key(service.upper()):
            return self.service_map[service.upper()]
        return False

    def channel_join_update(self, chan, join_time):
        self.join_map[chan] = ( Stats(), Stats(), Stats(), Stats() )
        self.channel_update(chan, self.STATS_JOIN, 1, t = join_time)
    def channel_join(self, chan = 0, delay = 2):
        '''Join a channel and create a send/recv stats map'''
        if self.join_map.has_key(chan):
            del self.join_map[chan]
        self.delay = delay
        chan, join_time = self.join(chan)
        self.channel_join_update(chan, join_time)
        return chan

    def channel_join_next(self, delay = 2):
        '''Joins the next channel leaving the last channel'''
        if self.last_chan:
            if self.join_map.has_key(self.last_chan):
                del self.join_map[self.last_chan]
        self.delay = delay
        chan, join_time = self.join_next()
        self.channel_join_update(chan, join_time)
        return chan

    def channel_jump(self, delay = 2):
        '''Jumps randomly to the next channel leaving the last channel'''
        if self.last_chan is not None:
            if self.join_map.has_key(self.last_chan):
                del self.join_map[self.last_chan]
        self.delay = delay
        chan, join_time = self.jump()
        self.channel_join_update(chan, join_time)
        return chan

    def channel_leave(self, chan = 0):
        if self.join_map.has_key(chan):
            del self.join_map[chan]
        self.leave(chan)

    def channel_update(self, chan, stats_type, packets, t=0):
        if type(chan) == type(0):
            chan_list = (chan,)
        else:
            chan_list = chan
        for c in chan_list:
            if self.join_map.has_key(c):
                self.join_map[c][stats_type].update(packets = packets, t = t)
    def channel_receive(self, chan, cb = None, count = 1, timeout = 5):
        log.info('Subscriber %s on port %s receiving from group %s, channel %d' %
                  (self.name, self.rx_intf, self.gaddr(chan), chan))
        r = self.recv(chan, cb = cb, count = count, timeout = timeout)
        if len(r) == 0:
            log.info('Subscriber %s on port %s timed out' %(self.name, self.rx_intf))
        else:
            log.info('Subscriber %s on port %s received %d packets' %(self.name, self.rx_intf, len(r)))
        if self.recv_timeout:
            ##Negative test case is disabled for now
            assert_equal(len(r), 0)

    def recv_channel_cb(self, pkt):
        ##First verify that we have received the packet for the joined instance
        log.info('Packet received for group %s, subscriber %s, port %s' %
                 (pkt[IP].dst, self.name, self.rx_intf))
        if self.recv_timeout:
            return
        chan = self.caddr(pkt[IP].dst)
        assert_equal(chan in self.join_map.keys(), True)
        recv_time = monotonic.monotonic() * 1000000
        join_time = self.join_map[chan][self.STATS_JOIN].start
        delta = recv_time - join_time
        self.join_rx_stats.update(packets=1, t = delta, usecs = True)
        self.channel_update(chan, self.STATS_RX, 1, t = delta)
        log.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))

class subscriber_pool:

    def __init__(self, subscriber, test_cbs):
        self.subscriber = subscriber
        self.test_cbs = test_cbs

    def pool_cb(self):
        for cb in self.test_cbs:
            if cb:
                self.test_status = cb(self.subscriber)
                if self.test_status is not True:
                    ## This is chaning for other sub status has to check again
                    self.test_status = True
                    log.info('This service is failed and other services will not run for this subscriber')
                    break
        log.info('This Subscriber is tested for multiple service eligibility ')
        self.test_status = True

class cluster_subscriber(object):
      apps = ('org.opencord.aaa', 'org.onosproject.dhcp')
      olt_apps = () #'org.opencord.cordmcast')
      vtn_app = 'org.opencord.vtn'
      table_app = 'org.ciena.cordigmp'
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

      aaa_loaded = False
      test_path = os.path.dirname(os.path.realpath(__file__))
      table_app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-multitable-2.0-SNAPSHOT.oar')
      app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-2.0-SNAPSHOT.oar')
      onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
      olt_conf_file = os.path.join(test_path, '..', 'setup/olt_config.json')
      cpqd_path = os.path.join(test_path, '..', 'setup')
      ovs_path = cpqd_path
      test_services = ('IGMP', 'TRAFFIC')
      num_joins = 0
      num_subscribers = 0
      num_channels = 0
      recv_timeout = False
      onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))

      INTF_TX_DEFAULT = 'veth2'
      INTF_RX_DEFAULT = 'veth0'
      SUBSCRIBER_TIMEOUT = 300
      CLIENT_CERT = """-----BEGIN CERTIFICATE-----
MIICuDCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBizELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5h
IEluYy4xHjAcBgkqhkiG9w0BCQEWD2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMd
RXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwNjA2MjExMjI3WhcN
MTcwNjAxMjExMjI3WjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNV
BAoTCkNpZW5hIEluYy4xFzAVBgNVBAMUDnVzZXJAY2llbmEuY29tMR0wGwYJKoZI
hvcNAQkBFg51c2VyQGNpZW5hLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAwvXiSzb9LZ6c7uNziUfKvoHO7wu/uiFC5YUpXbmVGuGZizbVrny0xnR85Dfe
+9R4diansfDhIhzOUl1XjN3YDeSS9OeF5YWNNE8XDhlz2d3rVzaN6hIhdotBkUjg
rUewjTg5OFR31QEyG3v8xR3CLgiE9xQELjZbSA07pD79zuUCAwEAAaNPME0wEwYD
VR0lBAwwCgYIKwYBBQUHAwIwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5l
eGFtcGxlLmNvbS9leGFtcGxlX2NhLmNybDANBgkqhkiG9w0BAQUFAAOBgQDAjkrY
6tDChmKbvr8w6Du/t8vHjTCoCIocHTN0qzWOeb1YsAGX89+TrWIuO1dFyYd+Z0KC
PDKB5j/ygml9Na+AklSYAVJIjvlzXKZrOaPmhZqDufi+rXWti/utVqY4VMW2+HKC
nXp37qWeuFLGyR1519Y1d6F/5XzqmvbwURuEug==
-----END CERTIFICATE-----"""

      CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIDvTCCAqWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBizELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5h
IEluYy4xHjAcBgkqhkiG9w0BCQEWD2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMd
RXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwMzExMTg1MzM2WhcN
MTcwMzA2MTg1MzM2WjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNV
BAoTCkNpZW5hIEluYy4xFzAVBgNVBAMUDnVzZXJAY2llbmEuY29tMR0wGwYJKoZI
hvcNAQkBFg51c2VyQGNpZW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAOxemcBsPn9tZsCa5o2JA6sQDC7A6JgCNXXl2VFzKLNNvB9PS6D7ZBsQ
5An0zEDMNzi51q7lnrYg1XyiE4S8FzMGAFr94RlGMQJUbRD9V/oqszMX4k++iAOK
tIA1gr3x7Zi+0tkjVSVzXTmgNnhChAamdMsjYUG5+CY9WAicXyy+VEV3zTphZZDR
OjcjEp4m/TSXVPYPgYDXI40YZKX5BdvqykWtT/tIgZb48RS1NPyN/XkCYzl3bv21
qx7Mc0fcEbsJBIIRYTUkfxnsilcnmLxSYO+p+DZ9uBLBzcQt+4Rd5pLSfi21WM39
2Z2oOi3vs/OYAPAqgmi2JWOv3mePa/8CAwEAAaNPME0wEwYDVR0lBAwwCgYIKwYB
BQUHAwIwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5leGFtcGxlLmNvbS9l
eGFtcGxlX2NhLmNybDANBgkqhkiG9w0BAQUFAAOCAQEALBzMPDTIB6sLyPl0T6JV
MjOkyldAVhXWiQsTjaGQGJUUe1cmUJyZbUZEc13MygXMPOM4x7z6VpXGuq1c/Vxn
VzQ2fNnbJcIAHi/7G8W5/SQfPesIVDsHTEc4ZspPi5jlS/MVX3HOC+BDbOjdbwqP
RX0JEr+uOyhjO+lRxG8ilMRACoBUbw1eDuVDoEBgErSUC44pq5ioDw2xelc+Y6hQ
dmtYwfY0DbvwxHtA495frLyPcastDiT/zre7NL51MyUDPjjYjghNQEwvu66IKbQ3
T1tJBrgI7/WI+dqhKBFolKGKTDWIHsZXQvZ1snGu/FRYzg1l+R/jT8cRB9BDwhUt
yg==
-----END CERTIFICATE-----'''
      @classmethod
      def load_device_id(cls):
            '''Configure the device id'''
            did = OnosCtrl.get_device_id()
            #Set the default config
            cls.device_id = did
            cls.device_dict = { "devices" : {
                        "{}".format(did) : {
                              "basic" : {
                                    "driver" : "pmc-olt"
                                    }
                              }
                        },
                  }
            return did

      @classmethod
      def setUpClass(cls,controller=None):
	  log.info('controller ip in cluster.py setupclass is %s'%controller)
          '''Load the OLT config and activate relevant apps'''
          did = cls.load_device_id()
          network_cfg = { "devices" : {
                  "{}".format(did) : {
                        "basic" : {
                              "driver" : "pmc-olt"
                              }
                        }
                  },
          }
          ## Restart ONOS with cpqd driver config for OVS
	  print('onos restart in setUpClass')
          cls.start_onos(network_cfg = network_cfg)
	  #status, code = OnosCtrl.config(network_cfg)
          #if status is False:
          #   log.info('JSON config request for app %s returned status %d' %(app, code))
          #assert_equal(status, True)
          #time.sleep(2)
          cls.install_app_table(controller=controller)
          cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
          OnosCtrl.cord_olt_config(cls.olt, controller=controller)
          cls.port_map, cls.port_list = cls.olt.olt_port_map()
          cls.activate_apps(cls.apps + cls.olt_apps,controller=controller)

      @classmethod
      def tearDownClass(cls,controller=None):
          '''Deactivate the olt apps and restart OVS back'''
          apps = cls.olt_apps + ( cls.table_app,)
          for app in apps:
              onos_ctrl = OnosCtrl(app,controller=controller)
              onos_ctrl.deactivate()
          cls.uninstall_app_table()
          cls.start_onos(network_cfg = {})

      @classmethod
      def activate_apps(cls, apps,controller=None):
            for app in apps:
                  onos_ctrl = OnosCtrl(app,controller=controller)
                  status, _ = onos_ctrl.activate()
                  assert_equal(status, True)
                  time.sleep(2)
      @classmethod
      def install_app_table(cls,controller=None):
            ##Uninstall the existing app if any
            OnosCtrl.uninstall_app(cls.table_app,onos_ip=controller)
            time.sleep(2)
            log.info('Installing the multi table app %s for subscriber test' %(cls.table_app_file))
            OnosCtrl.install_app(cls.table_app_file,onos_ip=controller)
            time.sleep(3)
            #onos_ctrl = OnosCtrl(cls.vtn_app)
            #onos_ctrl.deactivate()

      @classmethod
      def uninstall_app_table(cls,controller=None):
            ##Uninstall the table app on class exit
            OnosCtrl.uninstall_app(cls.table_app,onos_ip=controller)
            time.sleep(2)
            log.info('Installing back the cord igmp app %s for subscriber test on exit' %(cls.app_file))
            OnosCtrl.install_app(cls.app_file,onos_ip=controller)
            #onos_ctrl = OnosCtrl(cls.vtn_app)
            #onos_ctrl.activate()

      @classmethod
      def start_onos(cls, network_cfg = None):
            if cls.onos_restartable is False:
                  log.info('ONOS restart is disabled. Skipping ONOS restart')
                  return
            if network_cfg is None:
                  network_cfg = cls.device_dict

            if type(network_cfg) is tuple:
                  res = []
                  for v in network_cfg:
                        res += v.items()
                  config = dict(res)
            else:
                  config = network_cfg
            log.info('Restarting ONOS with new network configuration')
            #return cord_test_onos_restart(config = config)

      @classmethod
      def remove_onos_config(cls):
            try:
                  os.unlink('{}/network-cfg.json'.format(cls.onos_config_path))
            except: pass
      @classmethod
      def start_cpqd(cls, mac = '00:11:22:33:44:55'):
            dpid = mac.replace(':', '')
            cpqd_file = os.sep.join( (cls.cpqd_path, 'cpqd.sh') )
            cpqd_cmd = '{} {}'.format(cpqd_file, dpid)
            ret = os.system(cpqd_cmd)
            assert_equal(ret, 0)
            time.sleep(10)
            device_id = 'of:{}{}'.format('0'*4, dpid)
            return device_id

      @classmethod
      def start_ovs(cls):
            ovs_file = os.sep.join( (cls.ovs_path, 'of-bridge.sh') )
            ret = os.system(ovs_file)
            assert_equal(ret, 0)
            time.sleep(30)

      @classmethod
      def ovs_cleanup(cls):
            ##For every test case, delete all the OVS groups
            cmd = 'ovs-ofctl del-groups br-int -OOpenFlow11 >/dev/null 2>&1'
            cord_test_shell(cmd)
            ##Since olt config is used for this test, we just fire a careless local cmd as well
            try:
                  os.system(cmd)
            except: pass

      def onos_aaa_load(self,controller=None):
	    log.info('controller ip in cluster.py onos_aaa_load is %s'%controller)
            if self.aaa_loaded:
                  return
            aaa_dict = {'apps' : { 'org.opencord.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                    'radiusIp': '172.17.0.2' } } } }
            radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
            aaa_dict['apps']['org.opencord.aaa']['AAA']['radiusIp'] = radius_ip
            self.onos_load_config('org.opencord.aaa', aaa_dict,controller=controller)
            self.aaa_loaded = True

      def onos_dhcp_table_load(self, config = None,controller=None):
	  log.info('controller ip in cluster.py onos_dhcp_table_load is %s'%controller)
          dhcp_dict = {'apps' : { 'org.onosproject.dhcp' : { 'dhcp' : copy.copy(self.dhcp_server_config) } } }
          dhcp_config = dhcp_dict['apps']['org.onosproject.dhcp']['dhcp']
          if config:
              for k in config.keys():
                  if dhcp_config.has_key(k):
                      dhcp_config[k] = config[k]
          self.onos_load_config('org.onosproject.dhcp', dhcp_dict,controller=controller)

      def onos_load_config(self, app, config,controller=None):
	  log.info('controller ip in cluster.py onos_load_config is %s'%controller)
          status, code = OnosCtrl(controller=controller).config(config)
          if status is False:
             log.info('JSON config request for app %s returned status %d' %(app, code))
             assert_equal(status, True)
          time.sleep(2)
      def dhcp_sndrcv(self, dhcp, update_seed = False):
            cip, sip = dhcp.discover(update_seed = update_seed)
            assert_not_equal(cip, None)
            assert_not_equal(sip, None)
            log.info('Got dhcp client IP %s from server %s for mac %s' %
                     (cip, sip, dhcp.get_mac(cip)[0]))
            return cip,sip

      def dhcp_request(self, subscriber, seed_ip = '10.10.10.1', update_seed = False):
            config = {'startip':'10.10.10.20', 'endip':'10.10.10.200',
                      'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                      'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
            self.onos_dhcp_table_load(config)
            dhcp = DHCPTest(seed_ip = seed_ip, iface = subscriber.iface)
            cip, sip = self.dhcp_sndrcv(dhcp, update_seed = update_seed)
            return cip, sip

      def recv_channel_cb(self, pkt):
            ##First verify that we have received the packet for the joined instance
            chan = self.subscriber.caddr(pkt[IP].dst)
            assert_equal(chan in self.subscriber.join_map.keys(), True)
            recv_time = monotonic.monotonic() * 1000000
            join_time = self.subscriber.join_map[chan][self.subscriber.STATS_JOIN].start
            delta = recv_time - join_time
            self.subscriber.join_rx_stats.update(packets=1, t = delta, usecs = True)
            self.subscriber.channel_update(chan, self.subscriber.STATS_RX, 1, t = delta)
            log.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))
            self.test_status = True

      def traffic_verify(self, subscriber):
            if subscriber.has_service('TRAFFIC'):
                  url = 'http://www.google.com'
                  resp = requests.get(url)
                  self.test_status = resp.ok
                  if resp.ok == False:
                        log.info('Subscriber %s failed get from url %s with status code %d'
                                 %(subscriber.name, url, resp.status_code))
                  else:
                        log.info('GET request from %s succeeded for subscriber %s'
                                 %(url, subscriber.name))
                  return self.test_status

      def tls_verify(self, subscriber):
            if subscriber.has_service('TLS'):
                  time.sleep(2)
                  tls = TLSAuthTest(intf = subscriber.rx_intf)
                  log.info('Running subscriber %s tls auth test' %subscriber.name)
                  tls.runTest()
                  self.test_status = True
                  return self.test_status
            else:
                  self.test_status = True
                  return self.test_status
      def dhcp_verify(self, subscriber):
            if subscriber.has_service('DHCP'):
                  cip, sip = self.dhcp_request(subscriber, update_seed = True)
                  log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
                  subscriber.src_list = [cip]
                  self.test_status = True
                  return self.test_status
            else:
                  subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
                  self.test_status = True
                  return self.test_status

      def dhcp_jump_verify(self, subscriber):
            if subscriber.has_service('DHCP'):
                  cip, sip = self.dhcp_request(subscriber, seed_ip = '10.10.200.1')
                  log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
                  subscriber.src_list = [cip]
                  self.test_status = True
                  return self.test_status
            else:
                  subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
                  self.test_status = True
                  return self.test_status

      def dhcp_next_verify(self, subscriber):
            if subscriber.has_service('DHCP'):
                  cip, sip = self.dhcp_request(subscriber, seed_ip = '10.10.150.1')
                  log.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
                  subscriber.src_list = [cip]
                  self.test_status = True
                  return self.test_status
            else:
                  subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
                  self.test_status = True
                  return self.test_status
      def igmp_verify(self, subscriber):
            chan = 0
            if subscriber.has_service('IGMP'):
                  ##We wait for all the subscribers to join before triggering leaves
                  if subscriber.rx_port > 1:
                        time.sleep(5)
                  subscriber.channel_join(chan, delay = 0)
                  self.num_joins += 1
                  while self.num_joins < self.num_subscribers:
                        time.sleep(5)
                  log.info('All subscribers have joined the channel')
                  for i in range(10):
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
                        log.info('Leaving channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_leave(chan)
                        time.sleep(5)
                        log.info('Interface %s Join RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name,subscriber.join_rx_stats))
                        #Should not receive packets for this subscriber
                        self.recv_timeout = True
                        subscriber.recv_timeout = True
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
                        subscriber.recv_timeout = False
                        self.recv_timeout = False
                        log.info('Joining channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_join(chan, delay = 0)
                  self.test_status = True
                  return self.test_status

      def igmp_jump_verify(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for i in xrange(subscriber.num):
                        log.info('Subscriber %s jumping channel' %subscriber.name)
                        chan = subscriber.channel_jump(delay=0)
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
                        log.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
                        time.sleep(3)
                  log.info('Interface %s Jump RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status
      def igmp_next_verify(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for i in xrange(subscriber.num):
                        if i:
                              chan = subscriber.channel_join_next(delay=0)
                        else:
                              chan = subscriber.channel_join(i, delay=0)
                        log.info('Joined next channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count=1)
                        log.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
                        time.sleep(3)
                  log.info('Interface %s Join Next RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status

      def generate_port_list(self, subscribers, channels):
            return self.port_list[:subscribers]

      def subscriber_load(self, create = True, num = 10, num_channels = 1, channel_start = 0, port_list = [],controller=None):
            '''Load the subscriber from the database'''
            self.subscriber_db = SubscriberDB(create = create, services = self.test_services)
            if create is True:
                  self.subscriber_db.generate(num)
            self.subscriber_info = self.subscriber_db.read(num)
            self.subscriber_list = []
            if not port_list:
                  port_list = self.generate_port_list(num, num_channels)

            index = 0
            for info in self.subscriber_info:
                  self.subscriber_list.append(Subscriber(name=info['Name'],
                                                         service=info['Service'],
                                                         port_map = self.port_map,
                                                         num=num_channels,
                                                         channel_start = channel_start,
                                                         tx_port = port_list[index][0],
                                                         rx_port = port_list[index][1]))
                  if num_channels > 1:
                        channel_start += num_channels
                  index += 1

            #load the ssm list for all subscriber channels
            igmpChannel = IgmpChannel(controller=controller)
            ssm_groups = map(lambda sub: sub.channels, self.subscriber_list)
            ssm_list = reduce(lambda ssm1, ssm2: ssm1+ssm2, ssm_groups)
            igmpChannel.igmp_load_ssm_config(ssm_list)
      def subscriber_join_verify( self, num_subscribers = 10, num_channels = 1,
                                  channel_start = 0, cbs = None, port_list = [], negative_subscriber_auth = None,controller=None):
	  log.info('controller ip in cluster.py subscriber_join_verify is %s'%controller)
          self.test_status = False
          self.ovs_cleanup()
          subscribers_count = num_subscribers
          sub_loop_count =  num_subscribers
          self.subscriber_load(create = True, num = num_subscribers,
                               num_channels = num_channels, channel_start = channel_start, port_list = port_list,controller=controller)
          self.onos_aaa_load(controller=controller)
          self.thread_pool = ThreadPool(min(100, subscribers_count), queue_size=1, wait_timeout=1)

          chan_leave = False #for single channel, multiple subscribers
          if None in (cbs, negative_subscriber_auth):
                cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify, self.traffic_verify)
                chan_leave = True
          cbs_negative = cbs
          for subscriber in self.subscriber_list:
                subscriber.start()
                if negative_subscriber_auth is 'half' and sub_loop_count%2 is not 0:
                   cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify, self.traffic_verify)
                elif negative_subscriber_auth is 'onethird' and sub_loop_count%3 is not 0:
                   cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify, self.traffic_verify)
                else:
                   cbs = cbs_negative
                sub_loop_count = sub_loop_count - 1
                pool_object = subscriber_pool(subscriber, cbs)
                self.thread_pool.addTask(pool_object.pool_cb)
          self.thread_pool.cleanUpThreads()
          for subscriber in self.subscriber_list:
                subscriber.stop()
                if chan_leave is True:
                      subscriber.channel_leave(0)
          subscribers_count = 0
          return self.test_status
      def tls_invalid_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT_INVALID)
             tls.runTest()
             if tls.failTest == True:
                self.test_status = False
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

      def tls_no_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = '')
             tls.runTest()
             if tls.failTest == True:
                self.test_status = False
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

      def tls_self_signed_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT)
             tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

      def tls_non_ca_authrized_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT_NON_CA_AUTHORIZED)
             tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status
          else:
              self.test_status = True
              return self.test_status
      def tls_Nsubscribers_use_same_valid_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log.info('Running subscriber %s tls auth test' %subscriber.name)
             num_users = 3
             for i in xrange(num_users):
                 tls = TLSAuthTest(intf = 'veth{}'.format(i*2))
                 tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

      def dhcp_discover_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
             time.sleep(2)
             log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
             t1 = self.subscriber_dhcp_1release()
             self.test_status = True
             return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_1release(self, iface = INTF_RX_DEFAULT):
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
      def dhcp_client_reboot_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                  time.sleep(2)
                  log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                  tl = self.subscriber_dhcp_client_request_after_reboot()
                  self.test_status = True
                  return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_client_request_after_reboot(self, iface = INTF_RX_DEFAULT):
          #''' Client sends DHCP Request after reboot.'''

          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
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

                new_cip, new_sip = self.dhcp.only_request(cip, mac)
                if new_cip == None:
                        log.info("Got DHCP server NAK.")
                        assert_not_equal(new_cip, None)
                elif new_cip != None:
                        log.info("Got DHCP ACK.")
      def dhcp_client_renew_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_client_renew_time()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_client_renew_time(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac , lval = self.dhcp.only_discover()
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
                        log.info("Client 's Renewal time is :%s",lval)
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
      def dhcp_server_reboot_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_server_after_reboot()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status
      def subscriber_dhcp_server_after_reboot(self, iface = INTF_RX_DEFAULT):
          ''' DHCP server goes down.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
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
                onos_ctrl = OnosCtrl(self.dhcp_app)
                onos_ctrl.deactivate()
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
#               self.activate_apps(self.dhcp_app)
                onos_ctrl = OnosCtrl(self.dhcp_app)
                status, _ = onos_ctrl.activate()
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
      def dhcp_client_rebind_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_client_rebind_time()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_client_rebind_time(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
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
                        log.info("Client 's Rebind time is :%s",lval)
                        log.info("Generating delay till rebind time.")
                        time.sleep(lval)
                        log.info("Client Sending broadcast DHCP requests for renewing lease or for getting new ip.")
                        self.dhcp.after_T2 = True
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
      def dhcp_starvation_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_starvation()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_starvation(self, iface = INTF_RX_DEFAULT):
          '''DHCP starve'''
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

      def dhcp_same_client_multi_discovers_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_same_client_multiple_discover()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status
      def subscriber_dhcp_same_client_multiple_discover(self, iface = INTF_RX_DEFAULT):
          ''' DHCP Client sending multiple discover . '''
          config = {'startip':'10.10.10.20', 'endip':'10.10.10.69',
                    'ip':'10.10.10.2', 'mac': "ca:fe:ca:fe:ca:fe",
                    'subnet': '255.255.255.0', 'broadcast':'10.10.10.255', 'router':'10.10.10.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
          log.info('Got dhcp client IP %s from server %s for mac %s . Not going to send DHCPREQUEST.' %
                  (cip, sip, mac) )
          log.info('Triggering DHCP discover again.')
          new_cip, new_sip, new_mac , lval = self.dhcp.only_discover()
          if cip == new_cip:
                 log.info('Got same ip for 2nd DHCP discover for client IP %s from server %s for mac %s. Triggering DHCP Request. '
                          % (new_cip, new_sip, new_mac) )
          elif cip != new_cip:
                log.info('Ip after 1st discover %s' %cip)
                log.info('Map after 2nd discover %s' %new_cip)
                assert_equal(cip, new_cip)

      def dhcp_same_client_multi_request_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_same_client_multiple_request()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status
      def subscriber_dhcp_same_client_multiple_request(self, iface = INTF_RX_DEFAULT):
          ''' DHCP Client sending multiple repeat DHCP requests. '''
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
                print "Something went wrong."

      def dhcp_client_desired_ip_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_client_desired_address()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_client_desired_address(self, iface = INTF_RX_DEFAULT):
          '''DHCP Client asking for desired IP address.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.31', iface = iface)
          cip, sip, mac , lval = self.dhcp.only_discover(desired = True)
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
      def dhcp_client_request_pkt_with_non_offered_ip_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_server_nak_packet()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status

      def subscriber_dhcp_server_nak_packet(self, iface = INTF_RX_DEFAULT):
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover()
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

      def dhcp_client_requested_out_pool_ip_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_client_desired_address_out_of_pool()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status
      def subscriber_dhcp_client_desired_address_out_of_pool(self, iface = INTF_RX_DEFAULT):
          '''DHCP Client asking for desired IP address from out of pool.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.35', iface = iface)
          cip, sip, mac, lval = self.dhcp.only_discover(desired = True)
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

      def dhcp_client_specific_lease_scenario(self, subscriber):
          if subscriber.has_service('DHCP'):
                time.sleep(2)
                log.info('Running subscriber %s DHCP rediscover scenario test' %subscriber.name)
                tl = self.subscriber_dhcp_specific_lease_packet()
                self.test_status = True
                return self.test_status
          else:
              subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
              self.test_status = True
              return self.test_status
      def subscriber_dhcp_specific_lease_packet(self, iface = INTF_RX_DEFAULT):
          ''' Client sends DHCP Discover packet for particular lease time.'''
          config = {'startip':'20.20.20.30', 'endip':'20.20.20.69',
                   'ip':'20.20.20.2', 'mac': "ca:fe:ca:fe:ca:fe",
                   'subnet': '255.255.255.0', 'broadcast':'20.20.20.255', 'router':'20.20.20.1'}
          self.onos_dhcp_table_load(config)
          self.dhcp = DHCPTest(seed_ip = '20.20.20.45', iface = iface)
          log.info('Sending DHCP discover with lease time of 700')
          cip, sip, mac, lval = self.dhcp.only_discover(lease_time = True)

          log.info("Verifying Client 's IP and mac in DHCP Offer packet.")
          if (cip == None and mac != None):
                log.info("Verified that Client 's IP and mac in DHCP Offer packet are none, which is not expected behavior.")
                assert_not_equal(cip, None)
          elif lval != 700:
                log.info('Getting dhcp client IP %s from server %s for mac %s with lease time %s. That is not 700.' %
                         (cip, sip, mac, lval) )
                assert_not_equal(lval, 700)
