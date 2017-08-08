
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
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_quagga_restart
from portmaps import g_subscriber_port_map
import threading
from threading import current_thread
import time
import os
import json
log_test.setLevel('INFO')


class proxyarp_exchange(unittest.TestCase):

    apps = ('org.onosproject.vrouter','org.onosproject.proxyarp')
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

    @classmethod
    def setUpClass(cls):
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
    def proxyarp_host_unload(cls):
        index = 1
        for host,_ in cls.hosts_list:
            iface = cls.port_map[index]
            index += 1
            config_cmds = ('ifconfig {} 0'.format(iface), )
            for cmd in config_cmds:
		log_test.info('host unload command %s' % cmd)
                os.system(cmd)

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
        with open('{}/network-cfg.json'.format(cls.onos_config_path), 'w') as f:
            f.write(cfg)
        return cord_test_onos_restart()

    @classmethod
    def host_config_load(cls, host_config = None):
	for host in host_config:
	    status, code = OnosCtrl.host_config(host)
	    if status is False:
                log_test.info('JSON request returned status %d' %code)
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
    def proxyarp_activate(cls, deactivate = False):
        app = 'org.onosproject.proxyarp'
        onos_ctrl = OnosCtrl(app)
        if deactivate is True:
            onos_ctrl.deactivate()
        else:
            onos_ctrl.activate()
        time.sleep(3)

    @classmethod
    def proxyarp_config(cls, hosts = 1):
        proxyarp_configs = cls.generate_interface_config(hosts = hosts)
	cls.interface_config_load(interface_cfg = proxyarp_configs)
	hostcfg = cls.generate_host_config()
	cls.host_config_load(host_config = hostcfg)
        return proxyarp_configs

    def proxyarp_arpreply_verify(self, ingress, hostip, hostmac, PositiveTest=True):
	log_test.info('verifying arp reply for host ip %s host mac %s on interface %s'%(hostip ,hostmac ,self.port_map[ingress]))
	self.success = False
        def recv_task():
            def recv_cb(pkt):
                log_test.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                self.success = True if PositiveTest == True else False
            sniff(count=1, timeout=2, lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].hwsrc == hostmac,
                  prn = recv_cb, iface = self.port_map[ingress])
        t = threading.Thread(target = recv_task)
        t.start()
        pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst=hostip))
        log_test.info('sending arp request  for dest ip %s on interface %s' %
                 (hostip, self.port_map[ingress]))
        sendp( pkt, count = 10, iface = self.port_map[ingress])
        t.join()
	if PositiveTest:
            assert_equal(self.success, True)
	else:
	    assert_equal(self.success, False)

    def __proxyarp_hosts_verify(self, hosts = 1,PositiveTest = True):
        _,_,hosts_config = self.proxyarp_config(hosts = hosts)
	log_test.info('\nhosts_config %s and its type %s'%(hosts_config,type(hosts_config)))
        self.cliEnter()
        connected_hosts = json.loads(self.cli.hosts(jsonFormat = True))
        log_test.info('Discovered hosts: %s' %connected_hosts)
        #We read from cli if we expect less number of routes to avoid cli timeouts
        if hosts <= 10000:
            assert_equal(len(connected_hosts), hosts)
	ingress = hosts+1
	for hostip, hostmac in hosts_config:
	        self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = PositiveTest)
		time.sleep(1)
	self.cliExit()
        return True

    def test_proxyarp_with_1_host(self, hosts=1):
        res = self.__proxyarp_hosts_verify(hosts = hosts)
        assert_equal(res, True)
	#cls.proxyarp_host_unload()
    def test_proxyarp_with_10_hosts(self, hosts=10):
        res = self.__proxyarp_hosts_verify(hosts = hosts)
        assert_equal(res, True)
    def test_proxyarp_with_50_hosts(self, hosts=50):
        res = self.__proxyarp_hosts_verify(hosts = hosts)
        assert_equal(res, True)
    def test_proxyarp_app_with_disabling_and_re_enabling(self,hosts = 3):
	ports_map, egress_map,hosts_config = self.proxyarp_config(hosts = hosts)
	ingress = hosts+1
	for hostip, hostmac in hosts_config:
	    self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
	    time.sleep(1)
	log_test.info('Deactivating proxyarp  app and expecting not to get arp reply from ONOS')
	self.proxyarp_activate(deactivate = True)
	for hostip, hostmac in hosts_config:
	    self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = False)
	    time.sleep(1)
	log_test.info('activating proxyarp  app and expecting to get arp reply from ONOS')
	self.proxyarp_activate(deactivate = False)
	for hostip, hostmac in hosts_config:
            self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)

    def test_proxyarp_nonexisting_host(self,hosts = 1):
    	_,_,hosts_config = self.proxyarp_config(hosts = hosts)
	ingress = hosts + 2
	for host, mac in hosts_config:
	    self.proxyarp_arpreply_verify(ingress,host,mac,PositiveTest = True)
	new_host = hosts_config[-1][0].split('.')
	new_host[2] = str(int(new_host[2])+1)
	new_host = '.'.join(new_host)
	new_mac =  RandMAC()._fix()
	log_test.info('verifying arp reply for host ip %s on interface %s'%(new_host,self.port_map[ingress]))
	res=srp1(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst=new_host),timeout=2,iface=self.port_map[ingress])
	assert_equal(res, None)
	log_test.info('arp reply not seen for host ip %s on interface %s as expected'%(new_host,self.port_map[ingress]))
	hosts = hosts + 1
	_,_,hosts_config = self.proxyarp_config(hosts = hosts)
	for host in hosts_config:
	    if host[0] == new_host:
		new_mac = host[1]
	self.proxyarp_arpreply_verify(ingress,new_host,new_mac,PositiveTest = True)

    def test_proxyarp_removing_host(self,hosts = 3):
        ports_map, egress_map,hosts_config = self.proxyarp_config(hosts = hosts)
        ingress = hosts+1
        for hostip, hostmac in hosts_config:
            self.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)
	host_mac = hosts_config[0][1]
        log_test.info('removing host entry %s' % host_mac)
        self.cliEnter()
        hostentries = json.loads(self.cli.hosts(jsonFormat = True))
        for host in hostentries:
	    res = host_mac.upper() in host.values()
	    if res:
	 	break
	assert_equal(res, True)
        hostid = host_mac+'/'+'None'
        delete_host  = self.cli.host_remove(hostid)
        hostentries = json.loads(self.cli.hosts(jsonFormat = True))
	for host in hostentries:
            res = host_mac.upper() in host.values()
            if res:
                break
        assert_equal(res, False)
        self.proxyarp_arpreply_verify(ingress,hosts_config[0][0],host_mac,PositiveTest = False)
        time.sleep(1)
        self.cliExit()

    def test_proxyarp_concurrent_requests_with_multiple_host_and_different_interfaces(self,hosts = 10):
	ports_map, egress_map,hosts_config = self.proxyarp_config(hosts = hosts)
	self.success = True
	ingress = hosts+1
	ports = range(ingress,ingress+10)
	hostmac = []
	hostip = []
	for ip,mac in hosts_config:
	    hostmac.append(mac)
	    hostip.append(ip)
	success_dir = {}
	def verify_proxyarp(*r):
            ingress,hostmac,hostip = r[0],r[1],r[2]
            def mac_recv_task():
                def recv_cb(pkt):
		    log_test.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                    success_dir[current_thread().name] = True
		sniff(count=1, timeout=5,lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].hwsrc == hostmac,
                    prn = recv_cb, iface = self.port_map[ingress])
	    t = threading.Thread(target = mac_recv_task)
	    t.start()
	    pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst= hostip))
            log_test.info('sending arp request  for dest ip %s on interface %s' %
                 (hostip,self.port_map[ingress]))
            sendp(pkt, count = 10,iface = self.port_map[ingress])
            t.join()
	t = []
	for i in range(10):
	    t.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
	    t[i].start()
	for i in range(10):
            t[i].join()
        if len(success_dir) != 10:
                self.success = False
        assert_equal(self.success, True)

    def test_proxyarp_disabling_enabling_app_initiating_concurrent_requests(self,hosts = 10):
	'''Test sending arp requests to multiple host ips at once from different interfaces by disabling and re-enabling proxyarp app'''
        ports_map, egress_map,hosts_config = self.proxyarp_config(hosts = hosts)
        self.success = True
        ingress = hosts+1
        ports = range(ingress,ingress+10)
        hostmac = []
        hostip = []
        for ip,mac in hosts_config:
            hostmac.append(mac)
            hostip.append(ip)
        success_dir = {}
        def verify_proxyarp(*r):
            ingress,hostmac,hostip = r[0],r[1],r[2]
            def mac_recv_task():
                def recv_cb(pkt):
                    log_test.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                    success_dir[current_thread().name] = True
                sniff(count=1, timeout=5,lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].hwsrc == hostmac,
                    prn = recv_cb, iface = self.port_map[ingress])
            t = threading.Thread(target = mac_recv_task)
            t.start()
            pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst= hostip))
            log_test.info('sending arp request  for dest ip %s on interface %s' %
                 (hostip,self.port_map[ingress]))
            sendp(pkt, count = 10,iface = self.port_map[ingress])
            t.join()
        t1 = []
	#starting multi threading before proxyarp disable
        for i in range(10):
            t1.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
            t1[i].start()
        for i in range(10):
            t1[i].join()
        if len(success_dir) != 10:
                self.success = False
        assert_equal(self.success, True)
	self.proxyarp_activate(deactivate = True)
	#starting multi threading after proxyarp disable
	t2 = []
	self.success = False
	for i in range(10):
            t2.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
            t2[i].start()
        for i in range(10):
            t2[i].join()
        if len(success_dir) != 10:
                self.success = True
        assert_equal(self.success, False)
	self.proxyarp_activate(deactivate = False)
	#starting multi threading after proxyarp re-enable
	self.success = True
	t3 = []
	for i in range(10):
            t3.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
            t3[i].start()
        for i in range(10):
            t3[i].join()
        if len(success_dir) != 20:
                self.success = False
	assert_equal(self.success, True)

    def test_proxyarp_with_existing_and_non_existing_hostIPs_initiating_concurrent_requests(self,hosts = 5):
        ports_map, egress_map,hosts_config = self.proxyarp_config(hosts = hosts)
        self.success = True
        ingress = hosts+1
        ports = range(ingress,ingress+10)
        hostmac = []
        hostip = []
        for ip,mac in hosts_config:
            hostmac.append(mac)
            hostip.append(ip)
	#adding 5 non-existing host IPs to hostip list
	for i in range(1,6):
	    ip = hostip[-1].split('.')
	    ip[3] = str(int(ip[3])+int(i))
            ip = '.'.join(ip)
	    hostip.append(ip)
	    hostmac.append(RandMAC()._fix())
        success_dir = {}
	replied_hosts = []
        def verify_proxyarp(*r):
            ingress,hostmac,hostip = r[0],r[1],r[2]
            def mac_recv_task():
                def recv_cb(pkt):
                    log_test.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                    success_dir[current_thread().name] = True
		    replied_hosts.append(hostip)
                sniff(count=1, timeout=5,lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].psrc == hostip,
                    prn = recv_cb, iface = self.port_map[ingress])
            t = threading.Thread(target = mac_recv_task)
            t.start()
            pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst= hostip))
            log_test.info('sending arp request  for dest ip %s on interface %s' %
                 (hostip,self.port_map[ingress]))
            sendp(pkt, count = 10,iface = self.port_map[ingress])
            t.join()
        t = []
        for i in range(10):
            t.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
            t[i].start()
        for i in range(10):
            t[i].join()
        if len(success_dir) != 5 and len(replied_hosts) != 5:
                self.success = False
        assert_equal(self.success, True)
	for i in range(5):
	    if hostip[i] not in replied_hosts:
		self.success = False
	assert_equal(self.success, True)
