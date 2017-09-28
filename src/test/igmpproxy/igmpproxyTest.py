
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from twisted.internet import defer
from nose.tools import *
from nose.twistedtools import reactor, deferred
from scapy.all import *
from select import select as socket_select
import time, monotonic
import requests
import os
import random
import threading
from IGMP import *
from McastTraffic import *
from Stats import Stats
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from Channels import IgmpChannel
from CordLogger import CordLogger
from CordTestConfig import setup_module, teardown_module
from onosclidriver import OnosCliDriver
from CordTestUtils import get_mac, get_controller
from portmaps import g_subscriber_port_map
from CordTestUtils import log_test
log_test.setLevel('INFO')

class IGMPProxyTestState:

      def __init__(self, groups = [], df = None, state = 0):
            self.df = df
            self.state = state
            self.counter = 0
            self.groups = groups
            self.group_map = {} ##create a send/recv count map
            for g in groups:
                self.group_map[g] = (Stats(), Stats())

      def update(self, group, tx = 0, rx = 0, t = 0):
            self.counter += 1
            index = 0 if rx == 0 else 1
            v = tx if rx == 0 else rx
            if self.group_map.has_key(group):
                  self.group_map[group][index].update(packets = v, t = t)

      def update_state(self):
          self.state = self.state ^ 1

class igmpproxy_exchange(CordLogger):

    V_INF1 = 'veth0'
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
    MCAST_TRAFFIC_TIMEOUT = 20
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    max_packets = 100
    MAX_PORTS = 100
    proxy_app = 'org.opencord.igmpproxy'
    mcast_app = 'org.opencord.mcast'
    cord_config_app = 'org.opencord.config'
    test_path = os.path.dirname(os.path.realpath(__file__))
    proxy_device_id = OnosCtrl.get_device_id()
    controller = get_controller()
    app_files = [os.path.join(test_path, '..', 'apps/cord-config-3.0-SNAPSHOT.oar'), os.path.join(test_path, '..', 'apps/olt-app-3.0-SNAPSHOT.oar'), os.path.join(test_path, '..', 'apps/mcast-1.3.0-SNAPSHOT.oar'), os.path.join(test_path, '..', 'apps/onos-app-igmpproxy-1.1.0-SNAPSHOT.oar')]
    proxy_config_file = os.path.join(test_path, '..', 'igmpproxy/igmpproxyconfig.json')
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup/olt_config.json'))
    ROVER_TEST_TIMEOUT = 300 #3600*86
    ROVER_TIMEOUT = (ROVER_TEST_TIMEOUT - 100)
    ROVER_JOIN_TIMEOUT = 60
    VOLTHA_ENABLED = bool(int(os.getenv('VOLTHA_ENABLED', 0)))
    configs = {}
    proxy_interfaces_last = ()
    interface_to_mac_map = {}
    host_ip_map = {}
    MAX_PORTS = 100

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, _ = cls.olt.olt_port_map()
        if cls.VOLTHA_ENABLED is False:
            OnosCtrl.config_device_driver()
            OnosCtrl.cord_olt_config(cls.olt)
        time.sleep(2)
	cls.uninstall_cord_config_app()
	time.sleep(2)
	cls.install_igmpproxy()
	cls.igmp_proxy_setup()

    @classmethod
    def tearDownClass(cls):
        if cls.VOLTHA_ENABLED is False:
            OnosCtrl.config_device_driver(driver = 'ovs')
	#cls.igmp_proxy_cleanup()

    def setUp(self):
        ''' Activate the igmp proxy app'''
        super(igmpproxy_exchange, self).setUp()
        self.igmp_channel = IgmpChannel()

    def tearDown(self):
	super(igmpproxy_exchange, self).tearDown()

    @classmethod
    def uninstall_cord_config_app(cls):
        log_test.info('Uninstalling org.opencord.config 1.2 version app')
        OnosCtrl(cls.cord_config_app).deactivate()
        OnosCtrl.uninstall_app(cls.cord_config_app, onos_ip = cls.controller)

    @classmethod
    def install_igmpproxy(cls):
        for app in cls.app_files:
            OnosCtrl.install_app(app, onos_ip = cls.controller)
	    OnosCtrl(app).activate()

    @classmethod
    def igmp_proxy_setup(cls):
        did =  OnosCtrl.get_device_id()
        cls.proxy_device_id = did
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.port_map, _ = cls.olt.olt_port_map()
        #log_test.info('port map is %s'%cls.port_map)
        if cls.port_map:
            ##Per subscriber, we use 1 relay port
            try:
                proxy_port = cls.port_map[cls.port_map['relay_ports'][0]]
            except:
                proxy_port = cls.port_map['uplink']
            cls.proxy_interface_port = proxy_port
            cls.proxy_interfaces = (cls.port_map[cls.proxy_interface_port],)
        else:
            cls.proxy_interface_port = 100
            cls.proxy_interfaces = (g_subscriber_port_map[cls.proxy_interface_port],)
        cls.proxy_interfaces_last = cls.proxy_interfaces
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

            #configure igmp proxy  virtual interface
            proxy_ip = cls.get_host_ip(interface_list[0][0])
            proxy_mac = cls.get_mac(cls.port_map[cls.proxy_interface_port])
            interface_list.append((cls.proxy_interface_port, proxy_ip, proxy_mac))
            cls.onos_interface_load(interface_list)

    @classmethod
    def igmp_proxy_cleanup(cls):
        ##reset the ONOS port configuration back to default
        for config in cls.configs.items():
            OnosCtrl.delete(config)
        # if cls.onos_restartable is True:
        #     log_test.info('Cleaning up dhcp relay config by restarting ONOS with default network cfg')
        #     return cord_test_onos_restart(config = {})

    @classmethod
    def onos_load_config(cls, config):
        #log_test.info('onos load config is %s'%config)
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    @classmethod
    def onos_interface_load(cls, interface_list):
        interface_dict = { 'ports': {} }
        for port_num, ip, mac in interface_list:
            port_map = interface_dict['ports']
            port = '{}/{}'.format(cls.proxy_device_id, port_num)
            port_map[port] = { 'interfaces': [] }
            interface_list = port_map[port]['interfaces']
            interface_map = { 'ips' : [ '{}/{}'.format(ip, 24) ],
                              'mac' : mac,
                              'name': 'vir-{}'.format(port_num)
                            }
            interface_list.append(interface_map)

        #cls.onos_load_config(interface_dict)
        cls.configs['interface_config'] = interface_dict

    @classmethod
    def onos_igmp_proxy_config_load(cls, FastLeave = "false"):
	#cls.proxy_interface_port = 12
        proxy_connect_point = '{}/{}'.format(cls.proxy_device_id, cls.proxy_interface_port)
        log_test.info('\nRelay interface port is %s'%cls.proxy_interface_port)
        log_test.info('\nRelay interface is %s'%cls.port_map[cls.proxy_interface_port])
        log_test.info('\nConnect point is %s'%proxy_connect_point)
	cls.onos_load_config(cls.proxy_config_file,json_file=True)
        igmpproxy_dict = { "apps": {
                "org.onosproject.provider.lldp": {
                        "suppression": {
                                "deviceTypes": ["ROADM"],
                                "annotation": "{\"no-lldp\":null}"
                        }
                },
                "org.opencord.igmpproxy": {
                        "igmpproxy": {
                                "globalConnectPointMode": "true",
                                "globalConnectPoint": proxy_connect_point,
                                "UnsolicitedTimeOut": "2",
                                "MaxResp": "10",
                                "KeepAliveInterval": "120",
                                "KeepAliveCount": "3",
                                "LastQueryInterval": "2",
                                "LastQueryCount": "2",
                                "FastLeave": FastLeave,
                                "PeriodicQuery": "true",
                                "IgmpCos": "7",
                                "withRAUpLink": "true",
                                "withRADownLink": "true"
                        }
                },
                "org.opencord.mcast": {
                        "multicast": {
                                "ingressVlan": "222",
                                "egressVlan": "17"
                        }
                }
           }
	}

	"""igmpproxy_dict = {'apps':{
				'org.opencord.igmpproxy':{
						'igmpproxy':
                                                        {'globalConnectPointMode': 'true',
                                                        'globalConnectPoint': proxy_connect_point,
                                                        'UnsolicitedTimeOut': '2',
                                                        'MaxResp': '10',
                                                        'KeepAliveInterval': '120',
                                                        'KeepAliveCount': '3',
                                                        'LastQueryInterval': '2',
                                                        'LastQueryCount': '2',
                                                        'FastLeave': 'false',
                                                        'PeriodicQuery': 'true',
                                                        'IgmpCos': '7',
                                                        'withRAUpLink': 'true',
                                                        'withRADownLink': 'true'
                                                        }
                                                      },
				 'org.opencord.mcast':{
                                           'ingressVlan': '222',
                                            'egressVlan': '17'
                                        },
                                    }
				}"""
	device_dict = {'devices':{
                           cls.proxy_device_id: {
                               'basic': {
                                   'driver': 'default'
                                },
                                'accessDevice': {
                                   'uplink': '2',
                                   'vlan': '222',
                                   'defaultVlan': '1'
                                   }
                                }
			    }
		      }
	log_test.info('Igmp proxy dict is %s'%igmpproxy_dict)
        cls.onos_load_config(igmpproxy_dict)
	cls.onos_load_config(device_dict)
        cls.configs['relay_config'] = igmpproxy_dict
	cls.configs['device_config'] = device_dict

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
                 'arping -I {0} {1} -c 2'.format(iface, host),)
                 #'ifconfig {} 0'.format(iface), )
        for c in cmds:
	    log_test.info('Host load config command %s'%c)
            os.system(c)

    @classmethod
    def host_config_load(cls, host_config = None):
        for host in host_config:
            status, code = OnosCtrl.host_config(host)
            if status is False:
                log_test.info('JSON request returned status %d' %code)
                assert_equal(status, True)

    @classmethod
    def generate_host_config(cls,ip,mac):
        num = 0
        hosts_dict = {}
	hosts_list = [(ip,mac),]
        for host, mac in hosts_list:
            port = num + 1 if num < cls.MAX_PORTS - 1 else cls.MAX_PORTS - 1
            hosts_dict[host] = {'mac':mac, 'vlan':'none', 'ipAddresses':[host], 'location':{ 'elementId' : '{}'.format(cls.proxy_device_id), 'port': port}}
            num += 1
        return hosts_dict.values()


    @classmethod
    def get_mac(cls, iface):
        if cls.interface_to_mac_map.has_key(iface):
            return cls.interface_to_mac_map[iface]
        mac = get_mac(iface, pad = 0)
        cls.interface_to_mac_map[iface] = mac
        return mac

    def onos_ssm_table_load(self, groups, src_list = ['1.2.3.4'],flag = False):
          ssm_dict = {'apps' : { 'org.opencord.igmpproxy' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.opencord.igmpproxy']['ssmTranslate']
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
	  log_test.info('ONOS ssm table config dictionary is %s'%ssm_dict)
          self.onos_load_config(ssm_dict)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          self.igmp_channel.cord_port_table_load(cord_port_map)
          time.sleep(2)

    def random_mcast_ip(self,start_ip = '224.1.1.1', end_ip = '224.1.254.254'):
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
            log_test.info('Receive stats %s for group %s' %(rx_stats, g))

        log_test.info('IGMP test verification success')

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
                log_test.info('Received %d packets for group %s' %(rx, g))
        for g in leave_groups:
            rx = recvState.group_map[g][1].count
            assert_equal(rx, 0)

        log_test.info('IGMP test verification success')

    def mcast_traffic_timer(self):
          log_test.info('MCAST traffic timer expiry')
          self.mcastTraffic.stopReceives()

    def send_mcast_cb(self, send_state):
        for g in send_state.groups:
            send_state.update(g, tx = 1)
        return 0

    ##Runs in the context of twisted reactor thread
    def igmp_recv(self, igmpState):
        s = socket_select([self.recv_socket], [], [], 1.0)
        if self.recv_socket in s[0]:
              p = self.recv_socket.recv()
              try:
                    send_time = float(p.payload.load)
                    recv_time = monotonic.monotonic()
              except:
                    log_test.info('Unexpected Payload received: %s' %p.payload.load)
                    return 0
              #log_test.info( 'Recv in %.6f secs' %(recv_time - send_time))
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
	#log_test.info('sending igmp join packet %s'%pkt.show())
        sendp(pkt, iface=iface)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_join_recvQuery(self, groups, rec_queryCount = None, src_list = ['1.2.3.4'], ip_pkt = None, iface = 'veth0', delay = 2):
        self.onos_ssm_table_load(groups, src_list)
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_INCLUDE, mcaddr=g)
              gr.sources = src_list
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
        IGMPv3.fixup(pkt)
        if rec_queryCount == None:
            log_test.info('Sending IGMP join for group %s and waiting for one query packet and printing the packet' %groups)
            resp = srp1(pkt, iface=iface)
        else:
            log_test.info('Sending IGMP join for group %s and waiting for periodic query packets and printing one packet' %groups)
            resp = srp1(pkt, iface=iface)
#       resp = srp1(pkt, iface=iface) if rec_queryCount else srp3(pkt, iface=iface)
        resp[0].summary()
        log_test.info('Sent IGMP join for group %s and received a query packet and  printing packet' %groups)
        if delay != 0:
            time.sleep(delay)

    def send_igmp_leave(self, groups, src_list = [], ip_pkt = None, iface = 'veth0', delay = 2):
	log_test.info('entering into igmp leave function')
        igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                      gaddr=self.IP_DST)
        for g in groups:
              #gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_EXCLUDE, mcaddr=g)
              gr = IGMPv3gr(rtype=IGMP_V3_GR_TYPE_CHANGE_TO_INCLUDE, mcaddr=g)
              gr.sources = src_list
              igmp.grps.append(gr)
        if ip_pkt is None:
              ip_pkt = self.igmp_eth/self.igmp_ip
        pkt = ip_pkt/igmp
	log_test.info('igmp leave packet is %s'%pkt.show())
        IGMPv3.fixup(pkt)
        sendp(pkt, iface = iface)
        if delay != 0:
            time.sleep(delay)

    def verify_igmp_packets_on_proxy_interface(self,ip_dst=None,iface=None,count=1,positive_test = True):
	log_test.info('positive test variable inside verify_igmp_packets_on_proxy_interface function is %s'%positive_test)
	if not iface:
		iface = self.proxy_interfaces[0]
	if not ip_dst:
		ip_dst = self.IP_DST
        self.status = False if positive_test is True else True
	#log_test.info('self.status is %s'%self.status)
	try:
	    def igmp_recv_cb(pkt):
                log_test.info('igmp packet received on proxy interface %s'%pkt.show())
                #log_test.info('igmp packet received on proxy interface %s'%pkt[Raw].show())
                self.status = True if positive_test is True else False
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].proto == 2 and p[IP].dst==ip_dst, count=count, timeout = 5, iface=iface)
	    log_test.info('self.status is %s'%self.status)
            #assert_equal(self.status, True)
	except Exception as error:
	    log_test.info('Got Unexpected error %s'%error)
	    raise
        #assert_equal(self.status, True)

    @deferred(30)
    def test_igmpproxy_app_installation(self):
        df = defer.Deferred()
        def proxy_app_install(df):
            self.uninstall_cord_config_app()
	    auth = ('karaf','karaf')
	    url = 'http://%s:8181/onos/v1/applications'.format(self.controller)
	    for file in self.app_files:
                with open(file, 'rb') as payload:
                     res = requests.post(url,auth=auth,data=payload)
                     assert_equal(res.ok, True)
	    df.callback(0)
        reactor.callLater(0, proxy_app_install, df)
        return df

    @deferred(30)
    def test_igmpproxy_app_netcfg(self):
        df = defer.Deferred()
        def proxy_net_config(df):
            auth = ('karaf','karaf')
            net_cfg_url = 'http://172.17.0.2:8181/onos/v1/network/configuration/'.format(self.controller)
            with open(self.proxy_config_file, 'rb') as payload:
                 res = requests.post(net_cfg_url,auth=auth,data=payload)
                 ssert_equal(res.ok, True)
            df.callback(0)
        reactor.callLater(0, proxy_net_config, df)
        return df

    @deferred(15)
    def test_igmpproxy_for_first_join(self,iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
   	    self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
	    try:
                t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                t.start()
	        self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                t.join()
	        assert_equal(self.status, True)
	    except Exception as error:
		log_test.info('Igmp packet sent from subscriber interface, not received on proxy interface %s'%error)
		raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(20)
    def test_igmpproxy_for_two_joins_with_different_igmp_groups(self,iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
    	    for group in groups:
	        try:
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
		    assert_equal(self.status, True)
		except Exception as error:
                    log_test.info('Igmp packet sent from subscriber interface, not received on proxy interface %s'%error)
                    raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(30)
    def test_igmpproxy_for_igmp_join_with_proxy_app_deactivation(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
	    try:
		for group in groups:
		    positive_test = True if group is groups[0] else False
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface,kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = [groups[0]], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
		    assert_equal(self.status, True)
		    OnosCtrl(self.proxy_app).deactivate()
		    time.sleep(1)
            except Exception as error:
                log_test.info('Igmp packet sent from subscriber interface, not received on proxy interface %s'%error)
                raise
	    OnosCtrl(self.proxy_app).activate()
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(30)
    def test_igmpproxy_for_igmp_join_with_mcast_app_deactivation(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            try:
                for group in groups:
                    positive_test = True if group is groups[0] else False
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface,kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
		    assert_equal(self.status, True)
                    OnosCtrl(self.mcast_app).deactivate()
                    time.sleep(1)
            except Exception as error:
                log_test.info('Igmp packet sent from subscriber interface, not received on proxy interface %s'%error)
                raise
	    OnosCtrl(self.mcast_app).activate()
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(20)
    def test_igmpproxy_for_igmp_joins_on_non_proxy_interface(self, iface='veth0', non_proxy_iface='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
	    try:
                t1 = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                t2 = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface,kwargs = {'iface':non_proxy_iface,'positive_test':False})
                t1.start()
                t2.start()
                self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                         iface = iface)
                t1.join()
		assert_equal(self.status, True)
                t2.join()
		assert_equal(self.status, True)
            except Exception as error:
                log_test.info('Igmp packet sent from subscriber interface, not received on proxy interface %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(25)
    def test_igmpproxy_sending_group_specific_query_receiving_igmp_leave(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
	    try:
                self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                     iface = iface)
		time.sleep(1)
		t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'ip_dst':group[0], 'iface':iface})
	        t.start()
	        self.send_igmp_leave(group, src_list= [], delay=10, iface = iface)
	        t.join()
		assert_equal(self.status, True)
            except Exception as error:
                log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(40)
    def test_igmpproxy_verifying_group_specific_query_when_two_subscribers_leave_same_multicast_group_one_after_other(self,iface1='veth0',iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
            try:
                self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                          delay=1,iface = iface1)
                self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                         delay=1,iface = iface2)
                for iface in [iface1, iface2]:
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'ip_dst':group[0], 'iface':iface})
                    t.start()
                    time.sleep(1)
                    self.send_igmp_leave(group, src_list= [], delay=10, iface = iface)
                    t.join()
                    assert_equal(self.status, True)
            except Exception as error:
                log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(60)
    def test_igmpproxy_verifying_group_specific_query_sent_for_all_the_groups_after_subscriber_leaves(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip(), self.random_mcast_ip(), self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            try:
		self.send_igmp_join(groups = groups, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                          delay=1,iface = iface)
		threads = []
		for group in groups:
                    threads.append(threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'ip_dst':group, 'iface':iface, 'count':len(groups)}))
                for thread in threads:
		    thread.start()
                time.sleep(1)
                self.send_igmp_leave(groups, src_list= [], delay=11, iface = iface)
		for thread in threads:
                    thread.join()
                    assert_equal(self.status, True)
            except Exception as error:
                log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(25)
    def test_igmpproxy_fast_leave(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load(FastLeave='true')
            self.onos_ssm_table_load(group,src_list=src)
            try:
                self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                     iface = iface)
                time.sleep(1)
                t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'positive_test':False, 'ip_dst':group[0], 'iface':iface})
                t.start()
                self.send_igmp_leave(group, src_list= [], delay=10, iface = iface)
                t.join()
                assert_equal(self.status, True)
            except Exception as error:
                log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(30)
    def test_igmpproxy_for_igmp_join_for_same_group_with_different_source(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            sources = [self.randomsourceip(),self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=sources)
	    try:
                for source in sources:
                    positive_test = True if source is sources[0] else False
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface,kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = group, src_list = source, record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
                    assert_equal(self.status, True)
                    time.sleep(1)
            except:
		log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(20)
    def test_igmpproxy_after_proxy_interface_toggles(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = self.random_mcast_ip()
	    group2 = self.random_mcast_ip()
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load([group,group2],src_list=src)
            for toggle in ['Up','Down']:
                if toggle == 'Down':
                    log_test.info('Toggling proxy interface ')
                    os.system('ifconfig {} down'.format(self.proxy_interfaces[0]))
		    time.sleep(1)
                    os.system('ifconfig {} up'.format(self.proxy_interfaces[0]))
		    time.sleep(1)
		    group = group2
		try:
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
		    assert_equal(self.status, True)
		except:
		    log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
		    raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(20)
    def test_igmpproxy_after_subscriber_interface_toggles(self,iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = self.random_mcast_ip()
            group2 = self.random_mcast_ip()
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load([group,group2],src_list=src)
            for toggle in ['Up','Down']:
                if toggle == 'Down':
                    log_test.info('Toggling subscriber interface ')
                    os.system('ifconfig {} down'.format(iface))
                    time.sleep(1)
                    os.system('ifconfig {} up'.format(iface))
                    time.sleep(1)
                    group = group2
                try:
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = iface)
                    t.join()
		    assert_equal(self.status, True)
                except:
		    log_test.info('Igmp query not received on subscriber interface in response to leave sent %s'%error)
                    raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(20)
    def test_igmpproxy_with_join_and_verify_traffic(self):
        group = [self.random_mcast_ip()]
        src = [self.randomsourceip()]
        self.onos_igmp_proxy_config_load()
        self.onos_ssm_table_load(group,src_list=src)
        df = defer.Deferred()
        igmpState = IGMPProxyTestState(groups = group, df = df)
        igmpStateRecv = IGMPProxyTestState(groups = group, df = df)
        igmpStateList = (igmpState, igmpStateRecv)
        tx_intf = self.port_map[self.PORT_TX_DEFAULT]
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb, arg = igmpState)
        self.df = df
        self.mcastTraffic = mcastTraffic
        self.recv_socket = L3PacketSocket(iface = rx_intf, type = ETH_P_IP)

        def igmp_srp_task(stateList):
            igmpSendState, igmpRecvState = stateList
            if not mcastTraffic.isRecvStopped():
                self.igmp_recv(igmpRecvState)
                reactor.callLater(0, igmp_srp_task, stateList)
            else:
                self.mcastTraffic.stop()
                #log_test.info('Sending IGMP leave for groups: %s' %groups)
                self.send_igmp_leave(group , iface = rx_intf, delay = 2)
                self.recv_socket.close()
                self.igmp_verify_join(stateList)
                self.df.callback(0)
        self.send_igmp_join(group, iface = rx_intf)
        mcastTraffic.start()
        self.test_timer = reactor.callLater(self.MCAST_TRAFFIC_TIMEOUT, self.mcast_traffic_timer)
        reactor.callLater(0, igmp_srp_task, igmpStateList)
        return df

    @deferred(50)
    def test_igmpproxy_with_two_subscribers_joining_same_igmp_group_verifying_traffic(self, iface1='veth0', iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
            igmpState = IGMPProxyTestState(groups = group, df = df)
            IGMPProxyTestState(groups = group, df = df)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                   arg = igmpState)
            mcastTraffic.start()
            time.sleep(1)
            join_state = IGMPProxyTestState(groups = group)
	    try:
		for iface in [iface1, iface2]:
		    positive_test = True if iface is iface1 else False
	            log_test.info('iface is %s'%iface)
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              iface = iface)
                    t.join()
		    assert_equal(self.status, True)
                    status = self.igmp_recv_task(iface, group, join_state)
            except Exception as error:
		log_test.info('Got some unexpected error %s'%error)
                raise
	    mcastTraffic.stop()
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(30)
    def test_igmpproxy_with_two_subscribers_joining_different_igmp_group_verifying_traffic(self, iface1='veth0', iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
	    try:
		for group in groups:
                    igmpState = IGMPProxyTestState(groups = [group], df = df)
                    IGMPProxyTestState(groups = [group], df = df)
                    mcastTraffic = McastTraffic([group], iface= tx_intf, cb = self.send_mcast_cb,
                                   arg = igmpState)
                    mcastTraffic.start()
                    time.sleep(1)
                    join_state = IGMPProxyTestState(groups = [group])
		    iface = iface1 if group is groups[0] else iface2
		    log_test.info('iface is %s and group is %s'%(iface,group))
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              iface = iface)
                    t.join()
                    assert_equal(self.status, True)
		    status = self.igmp_recv_task(iface, [group], join_state)
		    mcastTraffic.stop()
            except:
		log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(30)
    def test_igmpproxy_with_leave_and_verify_traffic(self):
        group = [self.random_mcast_ip()]
	self.onos_igmp_proxy_config_load()
	self.onos_ssm_table_load(group)
        df = defer.Deferred()
        igmpState = IGMPProxyTestState(groups = group, df = df)
        IGMPProxyTestState(groups = group, df = df)
        tx_intf = self.port_map[self.PORT_TX_DEFAULT]
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                    arg = igmpState)
	mcastTraffic.start()
        t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
        t.start()
	self.send_igmp_join(group, iface = rx_intf,delay=1)
        t.join()
        assert_equal(self.status, True)
        join_state = IGMPProxyTestState(groups = group)
        status = self.igmp_recv_task(rx_intf, group, join_state)
	self.send_igmp_leave(group, delay = 10, iface = rx_intf)
	join_state = IGMPProxyTestState(groups = group)
	status = self.igmp_not_recv_task(rx_intf, group, join_state)
	log_test.info('verified status for igmp recv task %s'%status)
	assert status == 1 , 'EXPECTED RESULT'
	df.callback(0)
        return df

    @deferred(30)
    def test_igmpproxy_data_traffic_for_non_joined_group(self):
        groups = [self.random_mcast_ip(),self.random_mcast_ip()]
        src = [self.randomsourceip()]
        self.onos_igmp_proxy_config_load()
        self.onos_ssm_table_load(groups,src_list=src)
        df = defer.Deferred()
        igmpState = IGMPProxyTestState(groups = groups, df = df)
        IGMPProxyTestState(groups = groups, df = df)
        tx_intf = self.port_map[self.PORT_TX_DEFAULT]
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
        mcastTraffic = McastTraffic(groups, iface= tx_intf, cb = self.send_mcast_cb,
                                    arg = igmpState)
        mcastTraffic.start()
        t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
        t.start()
        self.send_igmp_join([groups[0]],src_list= src, iface = rx_intf,delay=1)
        t.join()
        assert_equal(self.status, True)
        join_state = IGMPProxyTestState(groups = [groups[0]])
        status = self.igmp_recv_task(rx_intf, [groups[0]], join_state)
        join_state = IGMPProxyTestState(groups = [groups[1]])
        status = self.igmp_not_recv_task(rx_intf, [groups[1]], join_state)
        log_test.info('verified status for igmp recv task %s'%status)
	mcastTraffic.stop()
        assert status == 1 , 'EXPECTED RESULT'
        df.callback(0)
        return df

    #fail
    @deferred(timeout=60)
    def test_igmpproxy_with_leave_and_join_loop(self):
        self.groups = ['226.0.1.1', '227.0.0.1', '228.0.0.1', '229.0.0.1', '230.0.0.1' ]
        self.src_list = ['3.4.5.6', '7.8.9.10']
	self.onos_igmp_proxy_config_load()
	self.onos_ssm_table_load(self.groups,src_list=self.src_list)
        df = defer.Deferred()
        #self.df = df
        self.iterations = 0
        self.num_groups = len(self.groups)
        self.MAX_TEST_ITERATIONS = 3
        rx_intf = self.port_map[self.PORT_RX_DEFAULT]
	self.send_igmp_leave(self.groups,src_list = [], iface=rx_intf,delay=5)

        def igmp_srp_task(v):
              if self.iterations < self.MAX_TEST_ITERATIONS:
                    if v == 1:
                          ##join test
                          self.num_groups = random.randint(0, len(self.groups))
			  log_test.info('self.num_groups var is %s'%self.num_groups)
			  try:
			      for group in self.groups[:self.num_groups]:
                                  t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                                  t.start()
                                  self.send_igmp_join(group,src_list = self.src_list,
                                              iface = rx_intf, delay = 1)
			          t.join()
				  assert_equal(self.status, True)
			  except:
				log_test.info('Got some unexpected error %s'%error)
			        raise
                    else:
                          self.send_igmp_leave(self.groups[:self.num_groups],
                                               src_list = [],
                                               iface = rx_intf, delay = 10)
                    self.iterations += 1
                    v ^= 1
                    reactor.callLater(1.0 + 0.5*self.num_groups,
                                      igmp_srp_task, v)
              else:
                    df.callback(0)
        reactor.callLater(0, igmp_srp_task, 1)
        return df

    def igmp_join_task(self, intf, groups, state, src_list = ['1.2.3.4']):
          self.onos_ssm_table_load(groups, src_list)
          igmp = IGMPv3(type = IGMP_TYPE_V3_MEMBERSHIP_REPORT, max_resp_code=30,
                        gaddr=self.IP_DST)
          for g in groups:
                gr = IGMPv3gr(rtype = IGMP_V3_GR_TYPE_INCLUDE, mcaddr = g)
                gr.sources = src_list
                igmp.grps.append(gr)

          for g in groups:
                state.group_map[g][0].update(1, t = monotonic.monotonic())

          pkt = self.igmp_eth/self.igmp_ip/igmp
          IGMPv3.fixup(pkt)
          sendp(pkt, iface=intf)
          log_test.debug('Returning from join task')

    def igmp_recv_task(self, intf, groups, join_state):
          recv_socket = L3PacketSocket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log_test.info('Verifying join interface %s should receive multicast data'%intf)
          while True:
                p = recv_socket.recv()
                if p.dst in groups and group_map[p.dst][0] == 0:
                      group_map[p.dst][0] += 1
                      group_map[p.dst][1] = monotonic.monotonic()
                      c = 0
                      for g in groups:
                            c += group_map[g][0]
                      if c == len(groups):
                            break
          for g in groups:
                join_start = join_state.group_map[g][0].start
                recv_time = group_map[g][1] * 1000000
                delta = (recv_time - join_start)
                log_test.info('Join for group %s received in %.3f usecs' %
                         (g, delta))

          recv_socket.close()
          log_test.debug('Returning from recv task')

    def igmp_not_recv_task(self, intf, groups, join_state):
	  log_test.info('Entering igmp not recv task loop')
          recv_socket = L2Socket(iface = intf, type = ETH_P_IP)
          group_map = {}
          for g in groups:
                group_map[g] = [0,0]

          log_test.info('Verifying join interface, should not receive any multicast data')
          self.NEGATIVE_TRAFFIC_STATUS = 1
          def igmp_recv_cb(pkt):
                log_test.info('Multicast packet %s received for left groups %s' %(pkt[IP].dst, groups))
                self.NEGATIVE_TRAFFIC_STATUS = 2
          sniff(prn = igmp_recv_cb, count = 1, lfilter = lambda p: IP in p and p[IP].dst in groups,
                timeout = 3, opened_socket = recv_socket)
          recv_socket.close()
          return self.NEGATIVE_TRAFFIC_STATUS

    def group_latency_check(self, groups):
          tasks = []
          self.send_igmp_leave(groups = groups,delay=10)
          join_state = IGMPProxyTestState(groups = groups)
          tasks.append(threading.Thread(target=self.igmp_join_task, args = ('veth0', groups, join_state,)))
          traffic_state = IGMPProxyTestState(groups = groups)
          mcast_traffic = McastTraffic(groups, iface= 'veth2', cb = self.send_mcast_cb,
                                       arg = traffic_state)
          mcast_traffic.start()
          tasks.append(threading.Thread(target=self.igmp_recv_task, args = ('veth0', groups, join_state)))
          for t in tasks:
                t.start()
          for t in tasks:
                t.join()

          mcast_traffic.stop()
          self.send_igmp_leave(groups = groups)
          return

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_1group_join_latency(self):
        groups = [self.random_mcast_ip()]
        df = defer.Deferred()
        def igmp_1group_join_latency():
              self.group_latency_check(groups)
              df.callback(0)
        reactor.callLater(0, igmp_1group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 10)
    def test_igmpproxy_with_2group_join_latency(self):
        groups = [self.MGROUP1, self.MGROUP1]
        df = defer.Deferred()
        def igmp_2group_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_2group_join_latency)
        return df

    @deferred(timeout=IGMP_QUERY_TIMEOUT + 100)
    def test_igmpproxy_with_Ngroup_join_latency(self):
        groups = ['239.0.1.1', '240.0.1.1', '241.0.1.1', '242.0.1.1']
        df = defer.Deferred()
        def igmp_Ngroup_join_latency():
            self.group_latency_check(groups)
            df.callback(0)
        reactor.callLater(0, igmp_Ngroup_join_latency)
        return df

    @deferred(70)
    def test_igmpproxy_with_join_rover_all(self,iface='veth0'):
	self.onos_igmp_proxy_config_load()
	df = defer.Deferred()
	def igmp_proxy_join_rover():
              s = (224 << 16) | 1
              #e = (225 << 24) | (255 << 16) | (255 << 16) | 255
              e = (224 << 16) | 10
              for i in xrange(s, e+1):
                  if i&0xff:
                      ip = '%d.%d.%d.%d'%((i>>16)&0xff, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
		  try:
                      t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                      t.start()
                      self.send_igmp_join(groups = [ip], ssm_load=True, iface = iface, delay=1)
                      t.join()
		  except:
		      raise
              df.callback(0)
        reactor.callLater(0, igmp_proxy_join_rover)
        return df

    @deferred(timeout=ROVER_TEST_TIMEOUT)
    def test_igmpproxy_with_join_rover(self):
          df = defer.Deferred()
          iface = self.get_igmp_intf()
          self.df = df
          self.count = 0
          self.timeout = 0
          self.complete = False
          def igmp_join_timer():
                self.timeout += self.ROVER_JOIN_TIMEOUT
                log_test.info('IGMP joins sent: %d' %self.count)
                if self.timeout >= self.ROVER_TIMEOUT:
                      self.complete = True
                reactor.callLater(self.ROVER_JOIN_TIMEOUT, igmp_join_timer)

          reactor.callLater(self.ROVER_JOIN_TIMEOUT, igmp_join_timer)
          self.start_channel = (224 << 24) | 1
          self.end_channel = (224 << 24) | 200 #(225 << 24) | (255 << 16) | (255 << 16) | 255
          self.current_channel = self.start_channel
          def igmp_join_rover(self):
                #e = (224 << 24) | 10
                chan = self.current_channel
                self.current_channel += 1
                if self.current_channel >= self.end_channel:
                      chan = self.current_channel = self.start_channel
                if chan&0xff:
                      ip = '%d.%d.%d.%d'%((chan>>24)&0xff, (chan>>16)&0xff, (chan>>8)&0xff, chan&0xff)
                      self.send_igmp_join([ip], delay = 0, ssm_load = False, iface = iface)
                      self.count += 1
                if self.complete == True:
                      log_test.info('%d IGMP joins sent in %d seconds over %s' %(self.count, self.timeout, iface))
                      self.df.callback(0)
                else:
                      reactor.callLater(0, igmp_join_rover, self)
          reactor.callLater(0, igmp_join_rover, self)
          return df

    #fail
    @deferred(timeout=IGMP_QUERY_TIMEOUT + 30)
    def test_igmpproxy_sends_periodic_general_query_on_subscriber_connected_segment(self,iface='veth0'):
	groups = [self.random_mcast_ip()]
	self.onos_igmp_proxy_config_load()
	self.onos_ssm_table_load(groups)
	self.send_igmp_join(groups)
	self.success = False
        df = defer.Deferred()
        def igmp_query_timeout():
              def igmp_query_cb(pkt):
		    log_test.info('received igmp query packet is %s'%pkt.show())
		    self.success = True
              sniff(prn = igmp_query_cb, count=1, lfilter = lambda p: IP in p and p[IP].proto == 2 and p[IP].dst == '224.0.0.1',
	                               timeout = self.IGMP_QUERY_TIMEOUT+2, iface = iface)
              df.callback(0)
        self.send_igmp_join(groups)
        self.test_timer = reactor.callLater(0,igmp_query_timeout)
	assert_equal(self.success, True)
        return df


    @deferred(timeout=IGMP_QUERY_TIMEOUT + 30)
    def test_igmpproxy_with_not_sending_periodic_general_query_on_proxy_connected_interface(self):
        groups = [self.random_mcast_ip()]
        self.onos_igmp_proxy_config_load()
        self.onos_ssm_table_load(groups)
        self.send_igmp_join(groups)
	self.success = False
        df = defer.Deferred()
        def igmp_query_timeout():
              def igmp_query_cb(pkt):
                    log_test.info('received igmp query packet on proxy connected interface %s'%pkt.show())
		    self.success = True
              sniff(prn = igmp_query_cb, count=1, lfilter = lambda p: IP in p and p[IP].proto == 2 and p[IP].dst == '224.0.0.1',
                                       timeout = self.IGMP_QUERY_TIMEOUT+2, iface = self.proxy_interfaces[0])
              df.callback(0)
        self.send_igmp_join(groups)
        self.test_timer = reactor.callLater(0,igmp_query_timeout)
	assert_equal(self.success, False)
        return df

    @deferred(50)
    def test_igmpproxy_two_joins_one_leave_from_same_subscriber_and_verify_traffic(self,iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
                for group in groups:
                    igmpState = IGMPProxyTestState(groups = [group], df = df)
                    IGMPProxyTestState(groups = [group], df = df)
                    mcastTraffic = McastTraffic([group], iface= tx_intf, cb = self.send_mcast_cb,
                                   arg = igmpState)
                    mcastTraffic.start()
                    time.sleep(1)
                    join_state = IGMPProxyTestState(groups = [group])
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              iface = iface)
                    t.join()
                    assert_equal(self.status, True)
                    status = self.igmp_recv_task(iface, [group], join_state)
                    if group is groups[1]:
                        log_test.info('sending leave for group %s'%group)
                        self.send_igmp_leave([group], delay = 11, iface = iface)
                        join_state = IGMPProxyTestState(groups = [group])
                        status = self.igmp_not_recv_task(rx_intf, [group], join_state)
                        log_test.info('verified status for igmp recv task %s'%status)
                        assert status == 1 , 'EXPECTED RESULT'
                        log_test.info('verifying subscriber receives igmp traffic for group %s'%groups[0])
			join_state = IGMPProxyTestState(groups = [groups[0]])
			status = self.igmp_recv_task(iface, [groups[0]], join_state)
		mcastTraffic.stop()
            except:
                log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    #fail
    @deferred(50)
    def test_igmpproxy_two_subscribers_joins_igmp_group_one_subscriber_goes_down_and_verify_traffic(self,iface1='veth0',iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
                igmpState = IGMPProxyTestState(groups = group, df = df)
                IGMPProxyTestState(groups = group, df = df)
                mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                arg = igmpState)
                mcastTraffic.start()
                time.sleep(1)
                join_state = IGMPProxyTestState(groups = group)
		for iface in [iface1, iface2]:
		    positive_test = True if iface is iface1 else False
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              iface = iface)
                    t.join()
                    assert_equal(self.status, True)
                    status = self.igmp_recv_task(iface, group, join_state)
                    if iface is iface2:
                        log_test.info('bringning donw iface %s'%iface)
                        os.system('ifconfig {} down'.format(iface))
                        time.sleep(1)
                        os.system('ifconfig {} up'.format(iface))
                        time.sleep(1)
                        status = self.igmp_not_recv_task(iface, group, join_state)
                        log_test.info('verified status for igmp recv task %s'%status)
                        assert status == 1 , 'EXPECTED RESULT'
                        log_test.info('verifying subscriber %s receives igmp traffic'%iface1)
                        status = self.igmp_recv_task(iface1, group, join_state)
                mcastTraffic.stop()
            except:
                log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    @deferred(50)
    def test_igmpproxy_two_subscribers_join_different_igmp_groups_one_subscriber_leaves_and_verifying_traffic(self, iface1='veth0', iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(),self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
                for group in groups:
                    igmpState = IGMPProxyTestState(groups = [group], df = df)
                    IGMPProxyTestState(groups = [group], df = df)
                    mcastTraffic = McastTraffic([group], iface= tx_intf, cb = self.send_mcast_cb,
                                   arg = igmpState)
                    mcastTraffic.start()
                    time.sleep(1)
                    join_state = IGMPProxyTestState(groups = [group])
		    iface = iface1 if group is groups[0] else iface2
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                    t.start()
                    self.send_igmp_join(groups = [group], src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              delay=1,iface = iface)
                    t.join()
                    assert_equal(self.status, True)
                    status = self.igmp_recv_task(iface, [group], join_state)
                    if group is groups[1]:
                        log_test.info('sending leave for group %s'%group)
			time.sleep(3)
                        t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                        t.start()
                        self.send_igmp_leave([group], delay = 15, iface = iface)
                        t.join()
                        assert_equal(self.status, True)
                        join_state = IGMPProxyTestState(groups = [group])
                        status = self.igmp_not_recv_task(iface, [group], join_state)
                        log_test.info('verified status for igmp recv task %s'%status)
                        assert status == 1 , 'EXPECTED RESULT'
                        log_test.info('verifying subscriber receives igmp traffic for group %s'%groups[0])
                        join_state = IGMPProxyTestState(groups = [groups[0]])
                        status = self.igmp_recv_task(iface1, [groups[0]], join_state)
                mcastTraffic.stop()
            except:
                log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
	return df

    @deferred(50)
    def test_igmpproxy_with_two_subscriber_joining_same_igmp_group_one_subscriber_doing_fast_leave_verifying_traffic(self, iface1='veth0', iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load(FastLeave='true')
            self.onos_ssm_table_load(group,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
                for iface in [iface1, iface2]:
                    igmpState = IGMPProxyTestState(groups = group, df = df)
                    IGMPProxyTestState(groups = group, df = df)
                    mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                   arg = igmpState)
                    mcastTraffic.start()
                    time.sleep(1)
                    join_state = IGMPProxyTestState(groups = group)
		    positive_test = True if iface is iface1 else False
                    t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface, kwargs = {'positive_test':positive_test})
                    t.start()
                    self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              delay=1,iface = iface)
                    t.join()
                    assert_equal(self.status, True)
                    status = self.igmp_recv_task(iface, group, join_state)
                    if iface is iface2:
                        log_test.info('sending leave for group %s'%group)
                        time.sleep(10)
                        self.send_igmp_leave(group, delay = 1, iface = iface)
                        join_state = IGMPProxyTestState(groups = group)
                        status = self.igmp_not_recv_task(iface, group, join_state)
                        log_test.info('verified status for igmp recv task %s'%status)
                        assert status == 1 , 'EXPECTED RESULT'
                        log_test.info('verifying subscriber receives igmp traffic for group %s'%group)
                        join_state = IGMPProxyTestState(groups = group)
                        status = self.igmp_recv_task(iface1, group, join_state)
                mcastTraffic.stop()
            except:
                log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    #fail
    @deferred(20)
    def test_igmpproxy_with_multicast_source_connected_on_proxy_interface(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            igmpState = IGMPProxyTestState(groups = group, df = df)
            IGMPProxyTestState(groups = group, df = df)
            mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                  arg = igmpState)
            mcastTraffic.start()
            time.sleep(1)
            join_state = IGMPProxyTestState(groups = group)
	    try:
                t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                t.start()
                self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                              delay=1,iface = iface)
                t.join()
                assert_equal(self.status, True)
                status = self.igmp_recv_task(iface, group, join_state)
                mcastTraffic.stop()
            except:
                log_test.info('Got some unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df

    #fail
    @deferred(20)
    def test_igmpproxy_which_drops_multicast_traffic_for_exclude_record_type_group(self, iface='veth0'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            group = [self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(group,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
               igmpState = IGMPProxyTestState(groups = group, df = df)
               IGMPProxyTestState(groups = group, df = df)
               mcastTraffic = McastTraffic(group, iface= tx_intf, cb = self.send_mcast_cb,
                                 arg = igmpState)
               mcastTraffic.start()
               time.sleep(1)
               join_state = IGMPProxyTestState(groups = group)
               t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
               t.start()
               self.send_igmp_join(groups = group, src_list = src,record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                              iface = iface)
               t.join()
               assert_equal(self.status, True)
               status = self.igmp_not_recv_task(iface, group, join_state)
               log_test.info('verified status for igmp recv task %s'%status)
               assert status == 1 , 'EXPECTED RESULT'
            except:
               log_test.info('Got some unexpected error %s'%error)
               raise
	    mcastTraffic.stop()
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
	return df

    #fail : exclude record type igmp join not forwarded to proxy interface
    @deferred(40)
    def test_igmpproxy_with_two_subscriber_joins_set_with_include_and_exclude_mode_record_types_verifying_traffic(self, iface1='veth0', iface2='veth4'):
        df = defer.Deferred()
        def igmp_proxy_test(df):
            groups = [self.random_mcast_ip(), self.random_mcast_ip()]
            src = [self.randomsourceip()]
            self.onos_igmp_proxy_config_load()
            self.onos_ssm_table_load(groups,src_list=src)
            tx_intf = self.port_map[self.PORT_TX_DEFAULT]
            rx_intf = self.port_map[self.PORT_RX_DEFAULT]
            try:
	       for group in groups:
	           iface = iface1 if group is groups[0] else iface2
		   r_type = IGMP_V3_GR_TYPE_INCLUDE if group is groups[0] else IGMP_V3_GR_TYPE_EXCLUDE
                   igmpState = IGMPProxyTestState(groups = [group], df = df)
                   IGMPProxyTestState(groups = [group], df = df)
                   mcastTraffic = McastTraffic([group], iface= tx_intf, cb = self.send_mcast_cb,
                                 arg = igmpState)
                   mcastTraffic.start()
                   time.sleep(1)
                   join_state = IGMPProxyTestState(groups = [group])
                   t = threading.Thread(target = self.verify_igmp_packets_on_proxy_interface)
                   t.start()
                   self.send_igmp_join(groups = [group], src_list = src,record_type = r_type,
                              delay=1,iface = iface)
                   t.join()
                   assert_equal(self.status, True)
		   if group is groups[0]:
		       status = self.igmp_recv_task(iface, [group], join_state)
		   else:
                       status = self.igmp_not_recv_task(iface, [group], join_state)
                       log_test.info('verified status for igmp recv task %s'%status)
                       assert status == 1 , 'EXPECTED RESULT'
            except:
               log_test.info('Got some unexpected error %s'%error)
               raise
            mcastTraffic.stop()
            df.callback(0)
        reactor.callLater(0, igmp_proxy_test, df)
        return df
