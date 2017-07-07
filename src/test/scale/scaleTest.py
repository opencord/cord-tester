#copyright 2016-present Ciena Corporation
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
import time
import os
import sys
import json
import requests
import random
from nose.tools import *
from scapy.all import *
from twisted.internet import defer
from nose.twistedtools import reactor, deferred
from CordTestUtils import *
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from SSHTestAgent import SSHTestAgent
from Channels import IgmpChannel
from IGMP import *
from CordLogger import CordLogger
from VSGAccess import VSGAccess
from CordTestUtils import log_test as log
from CordTestConfig import setup_module, running_on_ciab
from OnosCtrl import OnosCtrl
from CordContainer import Onos
from CordSubscriberUtils import CordSubscriberUtils, XosUtils
log.setLevel('INFO')

class scale_exchange(CordLogger):
    HOST = "10.1.0.1"
    USER = "vagrant"
    PASS = "vagrant"
    head_node = os.getenv('HEAD_NODE', 'prod')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    test_path = os.path.dirname(os.path.realpath(__file__))
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config.json'))
    restApiXos =  None
    cord_subscriber = None
    SUBSCRIBER_ACCOUNT_NUM = 100
    SUBSCRIBER_S_TAG = 500
    SUBSCRIBER_C_TAG = 500
    SUBSCRIBERS_PER_S_TAG = 8
    subscriber_info = []
    volt_subscriber_info = []
    restore_methods = []
    TIMEOUT=120
    NUM_SUBSCRIBERS = 100
    wan_intf_ip = '10.6.1.129'
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
    igmp_eth = Ether(dst = IGMP_DST_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST)
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    igmp_app = 'org.opencord.igmp'
    acl_app = 'org.onosproject.acl'
    aaa_app = 'org.opencord.aaa'
    app = 'org.onosproject.cli'
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    default_port_map = {
        PORT_TX_DEFAULT : INTF_TX_DEFAULT,
        PORT_RX_DEFAULT : INTF_RX_DEFAULT,
        INTF_TX_DEFAULT : PORT_TX_DEFAULT,
        INTF_RX_DEFAULT : PORT_RX_DEFAULT
        }
    vrouter_apps = ('org.onosproject.proxyarp', 'org.onosproject.hostprovider', 'org.onosproject.vrouter', 'org.onosproject.fwd')
    CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIEyTCCA7GgAwIBAgIJAN3OagiHm6AXMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNvbWV3aGVyZTETMBEGA1UE
CgwKQ2llbmEgSW5jLjEeMBwGCSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYw
JAYDVQQDDB1FeGFtcGxlIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNzAzMTEw
MDQ3NDNaFw0yMjEwMzEwMDQ3NDNaMIGLMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
Q0ExEjAQBgNVBAcMCVNvbWV3aGVyZTETMBEGA1UECgwKQ2llbmEgSW5jLjEeMBwG
CSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYwJAYDVQQDDB1FeGFtcGxlIENl
cnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALYkVvncfeRel/apXy5iODla5H7sUpU7a+pwT7nephmjKDh0GPX/t5GUwgkB
1zQAEj0IPoxZIfSAGSFP/mqTUK2sm7qerArih0E3kBRpnBKJZB/4r1OTZ04CsuRQ
QJOqcI0mZJWUKEcahN4yZvRyxeiCeFFoc0Nw787MQHhD9lZTqJUoAvautUe1GCjG
46DS4MzpWNGkqn5/ZC8lQ198AceMwf2pJRuOQg5cPwp65+dKNLUMLiSUV7JpvmAo
of4MHtGaBxKHESZ2jPiNTT2uKI/7KxH3Pr/ctft3bcSX2d4q49B2tdEIRzC0ankm
CrxFcq9Cb3MGaNuwWAtk3fOGKusCAwEAAaOCASwwggEoMB0GA1UdDgQWBBRtf8rH
zJW7rliW1eZnbVbSb3obfDCBwAYDVR0jBIG4MIG1gBRtf8rHzJW7rliW1eZnbVbS
b3obfKGBkaSBjjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQH
DAlTb21ld2hlcmUxEzARBgNVBAoMCkNpZW5hIEluYy4xHjAcBgkqhkiG9w0BCQEW
D2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAwwdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBB
dXRob3JpdHmCCQDdzmoIh5ugFzAMBgNVHRMEBTADAQH/MDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5jb20vZXhhbXBsZV9jYS5jcmwwDQYJKoZI
hvcNAQELBQADggEBAKWjORcBc1WK3r8mq88ipUC2UR1qvxdON4K/hd+rdAj0E/xA
QCJDORKno8f2MktqLfhU0amCVBvwdfmVFmVDtl38b1pu+mNFO+FDp04039Fd5ThM
iYmiQjnJ2IcAi/CILtrjURvJUPSOX9lviOtcla0HW94dgA9IDRs5frrWO9jkcxXR
+oz3LNMfVnXqhoHHQ1RtvqOozhEsUZZWY5MuUxRY25peeZ7m1vz+zDa/DbrV1wsP
dxOocmYdGFIAT9AiRnR4Jc/hqabBVNMZlGAA+2dELajpaHqb4yx5gBLVkT7VgHjI
7cp7jLRL7T+i4orZiAXpeEpAeOrP8r0DYTJi/8A=
-----END CERTIFICATE-----'''


    @classmethod
    def setUpCordApi(cls):
        num_subscribers = max(cls.NUM_SUBSCRIBERS, 10)
        cls.cord_subscriber = CordSubscriberUtils(num_subscribers,
                                                  account_num = cls.SUBSCRIBER_ACCOUNT_NUM,
                                                  s_tag = cls.SUBSCRIBER_S_TAG,
                                                  c_tag = cls.SUBSCRIBER_C_TAG,
                                                  subscribers_per_s_tag = cls.SUBSCRIBERS_PER_S_TAG)
        cls.restApiXos = XosUtils.getRestApi()

    @classmethod
    def setUpClass(cls):
        cls.controllers = get_controllers()
        cls.controller = cls.controllers[0]
        cls.cli = None
        cls.on_pod = running_on_pod()
        cls.on_ciab = running_on_ciab()
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.vcpes = cls.olt.get_vcpes()
        cls.vcpes_dhcp = cls.olt.get_vcpes_by_type('dhcp')
        cls.vcpes_reserved = cls.olt.get_vcpes_by_type('reserved')
        cls.dhcp_vcpes_reserved = [ 'vcpe{}.{}.{}'.format(i, cls.vcpes_reserved[i]['s_tag'], cls.vcpes_reserved[i]['c_tag'])
                                    for i in xrange(len(cls.vcpes_reserved)) ]
        cls.untagged_dhcp_vcpes_reserved = [ 'vcpe{}'.format(i) for i in xrange(len(cls.vcpes_reserved)) ]
        cls.container_vcpes_reserved = [ 'vcpe-{}-{}'.format(vcpe['s_tag'], vcpe['c_tag']) for vcpe in cls.vcpes_reserved ]
        vcpe_dhcp_reserved = None
        vcpe_container_reserved = None
        if cls.vcpes_reserved:
            vcpe_dhcp_reserved = cls.dhcp_vcpes_reserved[0]
            if cls.on_pod is False:
                vcpe_dhcp_reserved = cls.untagged_dhcp_vcpes_reserved[0]
            vcpe_container_reserved = cls.container_vcpes_reserved[0]

        cls.vcpe_dhcp_reserved = vcpe_dhcp_reserved
        cls.vcpe_container_reserved = vcpe_container_reserved
        dhcp_vcpe_offset = len(cls.vcpes_reserved)
        cls.dhcp_vcpes = [ 'vcpe{}.{}.{}'.format(i+dhcp_vcpe_offset, cls.vcpes_dhcp[i]['s_tag'], cls.vcpes_dhcp[i]['c_tag'])
                           for i in xrange(len(cls.vcpes_dhcp))  ]
        cls.untagged_dhcp_vcpes = [ 'vcpe{}'.format(i+dhcp_vcpe_offset) for i in xrange(len(cls.vcpes_dhcp)) ]
        cls.container_vcpes = [ 'vcpe-{}-{}'.format(vcpe['s_tag'], vcpe['c_tag']) for vcpe in cls.vcpes_dhcp ]
        vcpe_dhcp = None
        vcpe_container = None
        #cache the first dhcp vcpe in the class for quick testing
        if cls.vcpes_dhcp:
            vcpe_container = cls.container_vcpes[0]
            vcpe_dhcp = cls.dhcp_vcpes[0]
            if cls.on_pod is False:
                vcpe_dhcp = cls.untagged_dhcp_vcpes[0]
        cls.vcpe_container = vcpe_container_reserved or vcpe_container
        cls.vcpe_dhcp = vcpe_dhcp_reserved or vcpe_dhcp
        VSGAccess.setUp()
        cls.setUpCordApi()
        if cls.on_pod is True:
            cls.openVCPEAccess(cls.cord_subscriber.volt_subscriber_info)
	cls.activate_apps()

    @classmethod
    def activate_apps(cls, deactivate = False):
        for app in cls.vrouter_apps:
            onos_ctrl = OnosCtrl(app)
            if deactivate is False:
                onos_ctrl.activate()
            else:
                onos_ctrl.deactivate()
            time.sleep(2)
	OnosCtrl(cls.igmp_app).activate()
	OnosCtrl(cls.acl_app).activate()
	OnosCtrl(cls.aaa_app).activate()

    @classmethod
    def tearDownClass(cls):
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.cord_subscriber.volt_subscriber_info)

    def log_set(self, level = None, app = 'org.onosproject'):
        CordLogger.logSet(level = level, app = app, controllers = self.controllers, forced = True)

    @classmethod
    def config_restore(cls):
        """Restore the vsg test configuration on test case failures"""
        for restore_method in cls.restore_methods:
            restore_method()

    def get_system_cpu_usage(self):
        """ Getting compute node CPU usage """
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        return float(output)

    def vsg_for_external_connectivity(self, subscriber_index, reserved = False):
        if reserved is True:
            if self.on_pod is True:
                vcpe = self.dhcp_vcpes_reserved[subscriber_index]
            else:
                vcpe = self.untagged_dhcp_vcpes_reserved[subscriber_index]
        else:
            if self.on_pod is True:
                vcpe = self.dhcp_vcpes[subscriber_index]
            else:
                vcpe = self.untagged_dhcp_vcpes[subscriber_index]
        mgmt = 'eth0'
        host = '8.8.8.8'
        self.success = False
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp echo requests to external network 8.8.8.8')
        st, _ = getstatusoutput('ping -c 3 8.8.8.8')
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def vsg_xos_subscriber_create(self, index, subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return ''
        if subscriber_info is None:
            subscriber_info = self.cord_subscriber.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.cord_subscriber.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        subId = self.cord_subscriber.subscriberCreate(index, subscriber_info, volt_subscriber_info)
        if subId:
            #if the vsg instance was already instantiated, then reduce delay
            if c_tag % self.SUBSCRIBERS_PER_S_TAG == 0:
                delay = 350
            else:
                delay = 90
            log.info('Delaying %d seconds for the VCPE to be provisioned' %(delay))
            time.sleep(delay)
            log.info('Testing for external connectivity to VCPE %s' %(vcpe))
            self.vsg_for_external_connectivity(index)

        return subId

    def vsg_xos_subscriber_delete(self, index, subId = '', voltId = '', subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return
        self.cord_subscriber.subscriberDelete(index, subId = subId, voltId = voltId,
                                              subscriber_info = subscriber_info,
                                              volt_subscriber_info = volt_subscriber_info)

    def vsg_xos_subscriber_id(self, index):
        if self.on_pod is False:
            return ''
        return self.cord_subscriber.subscriberId(index)

    def onos_load_config(self, config):
        #log_test.info('onos load config is %s'%config)
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(2)

    def onos_ssm_table_load(self, groups, src_list = ['1.2.3.4'],flag = False):
          ssm_dict = {'apps' : { 'org.opencord.igmp' : { 'ssmTranslate' : [] } } }
          ssm_xlate_list = ssm_dict['apps']['org.opencord.igmp']['ssmTranslate']
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
          self.onos_load_config(ssm_dict)
          cord_port_map = {}
          for g in groups:
                cord_port_map[g] = (self.PORT_TX_DEFAULT, self.PORT_RX_DEFAULT)
          IgmpChannel().cord_port_table_load(cord_port_map)
          time.sleep(2)

    def generate_random_multicast_ip_addresses(self,count=500):
        multicast_ips = []
        while(count >= 1):
                ip = '.'.join([str(random.randint(224,239)),str(random.randint(1,254)),str(random.randint(1,254)),str(random.randint(1,254))])
                if ip in multicast_ips:
                    pass
                else:
                    multicast_ips.append(ip)
                    count -= 1
        return multicast_ips

    def generate_random_unicast_ip_addresses(self,count=500):
        unicast_ips = []
        while(count >= 1):
                ip = '.'.join([str(random.randint(11,126)),str(random.randint(1,254)),str(random.randint(1,254)),str(random.randint(1,254))])
                if ip in unicast_ips:
                    pass
                else:
                    unicast_ips.append(ip)
                    count -= 1
        return unicast_ips

    def iptomac(self, mcast_ip):
        mcast_mac =  '01:00:5e:'
        octets = mcast_ip.split('.')
        second_oct = int(octets[1]) & 127
        third_oct = int(octets[2])
        fourth_oct = int(octets[3])
        mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
        return mcast_mac

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
        log.info('sending igmp join packet %s'%pkt.show())
        sendp(pkt, iface=iface)
        time.sleep(delay)

    def send_multicast_data_traffic(self, group, intf= 'veth2',source = '1.2.3.4'):
        dst_mac = self.iptomac(group)
        eth = Ether(dst= dst_mac)
        ip = IP(dst=group,src=source)
        data = repr(monotonic.monotonic())
        sendp(eth/ip/data,count=20, iface = intf)

    def verify_igmp_data_traffic(self, group, intf='veth0', source='1.2.3.4' ):
        log_test.info('verifying multicast traffic for group %s from source %s'%(group,source))
        self.success = False
        def recv_task():
            def igmp_recv_cb(pkt):
                #log_test.info('received multicast data packet is %s'%pkt.show())
                log_test.info('multicast data received for group %s from source %s'%(group,source))
                self.success = True
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].dst == group and p[IP].src == source, count=1,timeout = 2, iface='veth0')
        t = threading.Thread(target = recv_task)
        t.start()
        self.send_multicast_data_traffic(group,source=source)
        t.join()
        return self.success

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

    def to_egress_ip(self, ip):
        lst=ip.split('.')
        lst[0] = '182'
        return '.'.join(lst)

    @classmethod
    def start_onos(cls, network_cfg = None):
        if type(network_cfg) is tuple:
            res = []
            for v in network_cfg:
                res += v.items()
            config = dict(res)
        else:
            config = network_cfg
        log_test.info('Restarting ONOS with new network configuration')
        return cord_test_onos_restart(config = config)

    @classmethod
    def start_quagga(cls, networks = 4, peer_address = None, router_address = None):
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
        #log_test.info('Zebra routes: \n:%s\n' %cls.zebra_conf + zebra_routes)
        return cls.zebra_conf + zebra_routes

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
        log_test.info('Discovered hosts: %s' %hosts)
        ##We read from cli if we expect less number of routes to avoid cli timeouts
        if networks <= 10000:
            routes = json.loads(self.cli.routes(jsonFormat = True))
            #log_test.info('Routes: %s' %routes)
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
            #log_test.info('Flows: %s' %flows)
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
            log_test.info('Deactivating vrouter app in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = True)
            #routes = json.loads(self.cli.routes(jsonFormat = False, cmd_exist = False))
            #assert_equal(len(routes['routes4']), 'Command not found')
            log_test.info('Activating vrouter app again in ONOS controller for negative scenario')
            self.vrouter_activate(deactivate = False)
            routes = json.loads(self.cli.routes(jsonFormat = True))
            assert_equal(len(routes['routes4']), networks)
            self.vrouter_traffic_verify()
        self.cliExit()
        self.vrouter_host_unload()
        return True

    def onos_aaa_config(self):
        aaa_dict = {'apps' : { self.app : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                      'radiusIp': '172.17.0.2' } } } }
        radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
        aaa_dict['apps'][self.app]['AAA']['radiusIp'] = radius_ip
        self.onos_ctrl.activate()
        time.sleep(2)
        self.onos_load_config(aaa_dict)

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('Configure request for AAA returned status %d' %code)
            assert_equal(status, True)
            time.sleep(3)

    def test_scale_for_vsg_vm_creations(self):
        for index in xrange(len(self.cord_subscriber.subscriber_info)):
            #check if the index exists
            subId = self.vsg_xos_subscriber_id(index)
            log.info('test_vsg_xos_subscriber_creation')
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)
            subId = self.vsg_xos_subscriber_create(index)
            log.info('Created Subscriber %s' %(subId))

    def test_scale_for_vcpe_creations(self):
        for index in xrange(len(self.cord_subscriber.subscriber_info)):
            #check if the index exists
            subId = self.vsg_xos_subscriber_id(index)
            log.info('test_vsg_xos_subscriber_creation')
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)
            subId = self.vsg_xos_subscriber_create(index)
            log.info('Created Subscriber %s' %(subId))

    def test_scale_of_subcriber_vcpe_creations_in_single_vsg_vm(self):
        subId = self.vsg_xos_subscriber_create(100)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(100, subId)

    def test_scale_of_subcriber_vcpe_creations_in_multiple_vsg_vm(self):
        subId = self.vsg_xos_subscriber_create(100)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(100, subId)

    def test_scale_of_subcriber_vcpe_creations_with_one_vcpe_in_one_vsg_vm(self):
        subId = self.vsg_xos_subscriber_create(100)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(100, subId)

    def test_scale_for_cord_subscriber_creation_and_deletion(self):
        subId = self.vsg_xos_subscriber_create(100)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(100, subId)

    def test_cord_for_scale_of_subscriber_containers_per_compute_node(self):
        pass

    def test_latency_of_cord_for_control_packets_using_icmp_packet(self):
        cmd = "ping -c 4 {0} | tail -1| awk '{{print $4}}'".format(self.wan_intf_ip)
        st, out = getstatusoutput(cmd)
        if out != '':
                out = out.split('/')
                avg_rtt = out[1]
                latency = float(avg_rtt)/float(2)
        else:
            latency = None
        log.info('CORD setup latency calculated from icmp packet is = %s ms'%latency)
        assert_not_equal(latency,None)

    def test_latency_of_cord_for_control_packets_using_increasing_sizes_of_icmp_packet(self):
        pckt_sizes = [100,500,1000,1500]
        for size in pckt_sizes:
            cmd = "ping -c 4 -s {} {} | tail -1| awk '{{print $4}}'".format(size,self.wan_intf_ip)
            st, out = getstatusoutput(cmd)
            if out != '':
                out = out.split('/')
                avg_rtt = out[1]
                latency = float(avg_rtt)/float(2)
            else:
                latency = None
            log.info('CORD setup latency calculated from icmp packet with size %s bytes is = %s ms'%(size,latency))
            assert_not_equal(latency,None)

    def test_latency_of_cord_with_traceroute(self):
        cmd = "traceroute -q1 {} | tail -1| awk '{{print $4}}'".format(self.wan_intf_ip)
        avg_rtt = float(0)
        latency = None
        for index in [1,2,3]:
            st, out = getstatusoutput(cmd)
            if out != '':
                avg_rtt += float(out)
        latency = float(avg_rtt)/float(6)
        log.info('CORD setup latency calculated from  traceroute is = %s ms'%latency)
        assert_not_equal(latency,0.0)

    def test_scale_with_igmp_joins_for_500_multicast_groups_and_check_cpu_usage(self, group_count=500):
        OnosCtrl(self.igmp_app).activate()
        groups = self.generate_random_multicast_ip_addresses(count = group_count)
        sources = self.generate_random_unicast_ip_addresses(count = group_count)
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for index in range(group_count):
            self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))

    def test_scale_with_igmp_joins_for_1000_multicast_groups_and_check_cpu_usage(self, group_count=1000):
        OnosCtrl(self.igmp_app).activate()
        groups = self.generate_random_multicast_ip_addresses(count = group_count)
        sources = self.generate_random_unicast_ip_addresses(count = group_count)
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for index in range(group_count):
            self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))

    def test_scale_with_igmp_joins_for_2000_multicast_groups_and_check_cpu_usage(self, group_count=2000):
        OnosCtrl(self.igmp_app).activate()
        groups = self.generate_random_multicast_ip_addresses(count = group_count)
        sources = self.generate_random_unicast_ip_addresses(count = group_count)
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for index in range(group_count):
            self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))

    def test_scale_of_igmp_joins_for_2000_multicast_groups_and_check_cpu_usage_after_app_deactivation_and_activation(self,group_count=500):
        OnosCtrl(self.igmp_app).activate()
        groups = self.generate_random_multicast_ip_addresses(count = group_count)
        sources = self.generate_random_unicast_ip_addresses(count = group_count)
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for index in range(group_count):
            self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
        OnosCtrl(self.igmp_app).deactivate()
        time.sleep(1)
        cpu_usage = self.get_system_cpu_usage()
        log.info('CPU usage is %s for multicast group entries %s after igmp app deactivated'%(cpu_usage,index+1))

    def test_scale_adding_1k_flow_entries_in_onos_with_dynamic_tcp_ports(self,count=1000):
        cpu_usage1 = self.get_system_cpu_usage()
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': random.randint(1024,65535) }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': random.randint(1024,65535) }
        for index in range(0,count):
            ingress_map['tcp_port'] = random.randint(1024,65535)
            egress_map['tcp_port'] = random.randint(1024,65535)
            flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + self.port_offset,
                                ingressPort = ingress + self.port_offset,
                                tcpSrc = ingress_map['tcp_port'],
                                tcpDst = egress_map['tcp_port']
                                )
            result = flow.addFlow()
            assert_equal(result, True)
            log_test.info("flow number = %d is added",index+1)
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for flow number %d added'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_5k_constant_source_ip_flow_entries_in_onos_and_checking_cpu_usage(self,count=5000):
        cpu_usage1 = self.get_system_cpu_usage()
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
        for i in range(0,count):
            ingress_map['ip'] =  self.next_ip(ingress_map['ip'])
            assert_not_equal(ingress_map['ip'], None)
            egress_map['ip'] =  self.to_egress_ip(ingress_map['ip'])

            flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + self.port_offset,
                                ingressPort = ingress + self.port_offset,
                                ethType = '0x0800',
                                ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
                                ipDst = ('IPV4_DST', egress_map['ip']+'/8')
                                )
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for flow number %d added'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_10k_flow_entries_in_onos_with_dynamic_udp_ports(self,count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': random.randint(1024,65535) }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': random.randint(1024,65535) }
        for index in range(0,count):
            ingress_map['tcp_port'] = random.randint(1024,65535)
            egress_map['tcp_port'] = random.randint(1024,65535)
            flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + self.port_offset,
                                ingressPort = ingress + self.port_offset,
                                tcpSrc = ingress_map['tcp_port'],
                                tcpDst = egress_map['tcp_port']
                                )
            result = flow.addFlow()
            assert_equal(result, True)
            ##wait for flows to be added to ONOS
            log_test.info("flow number = %d is added",index+1)
            if index % 50 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for flow number %d added'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_10k_constant_destination_mac_flow_entries_in_onos_and_check_cpu_usage(self,count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '02:00:00:00:00:00'
        for index in range(0,count):
            ingress_mac = self.next_mac(ingress_mac)
            flow = OnosFlowCtrl(deviceId = self.device_id,
                        egressPort = egress + self.port_offset,
                        ingressPort = ingress + self.port_offset,
                        ethSrc = ingress_mac,
                        ethDst = egress_mac)
            result = flow.addFlow()
            assert_equal(result, True)
            log.info("flow number = %d is added",index+1)
            if index % 100 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_10k_acl_rules_to_deny_matching_destination_tcp_port_traffic(self,count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        acl_rule = ACLTest()
        for index in range(0,count):
            src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_port = random.randint(1024,65535)
            log.info('adding acl rule = %d with src ip = %s, dst ip = %s and dst tcp port = %d'%(index+1, src_ip,dst_ip,dst_port))
            status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip, ipProto ='TCP', dstTpPort =dst_port, action = 'deny')
            assert_equal(status, True)
            if index % 100 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_and_deleting_10k_acl_rules_to_allow_src_and_dst_ip_matching_traffic_check_cpu_usage(self,count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        acl_rule = ACLTest()
        for index in range(0,count):
            src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_port = random.randint(1024,65535)
            log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
            status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'allow')
            assert_equal(status, True)
            if index % 100 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for acl rule number %s'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        result = acl_rule.get_acl_rules()
        result = result.json()['aclRules']
        for acl in result:
                acl_rule.remove_acl_rule(acl['id'])
                #log.info('acl is %s'%acl)
        cpu_usage3 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f and after %d flows added = %f, after deleting all acl rules = %f'%(cpu_usage1,count,cpu_usage2,cpu_usage3))

    def test_scale_adding_20k_acl_rules_to_allow_src_and_dst_ip_matching_traffic_and_deactivate_acl_app_checking_cpu_usage(self,count=20000):
        cpu_usage1 = self.get_system_cpu_usage()
        acl_rule = ACLTest()
        for index in range(0,count):
            src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_port = random.randint(1024,65535)
            log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
            status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'allow')
            assert_equal(status, True)
            if index % 200 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for acl rule number %s'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        OnosCtrl(cls.acl_app).deactivate()
        time.sleep(3)
        cpu_usage3 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f, after %d flows added = %f, and after deactivating acl app = %f'%(cpu_usage1,count,cpu_usage2,cpu_usage3))

    def test_scale_adding_igmp_and_acl_with_flow_entries_and_check_cpu_usage(self,igmp_groups=1300, flows_count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        egress = 1
        ingress = 2
        egress_mac = '00:00:00:00:01:01'
        ingress_mac = '02:00:00:00:00:00'
        acl_rule = ACLTest()
        OnosCtrl(self.igmp_app).activate()
        groups = self.generate_random_multicast_ip_addresses(count = igmp_groups)
        sources = self.generate_random_unicast_ip_addresses(count = igmp_groups)
        self.onos_ssm_table_load(groups,src_list=sources,flag=True)
        for index in range(igmp_groups):
            self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
            status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
            assert_equal(status, True)
            log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
        for index in range(flows_count):
            src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
            log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
            status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'allow')
            assert_equal(status, True)
            ingress_mac = self.next_mac(ingress_mac)
            flow = OnosFlowCtrl(deviceId = self.device_id,
                        egressPort = egress + self.port_offset,
                        ingressPort = ingress + self.port_offset,
                        ethSrc = ingress_mac,
                        ethDst = egress_mac)
            result = flow.addFlow()
            assert_equal(result, True)
            log.info("flow number = %d is added",index+1)
            if index % 200 == 0:
                cpu_usage = self.get_system_cpu_usage()
                log.info('CPU usage is %s for acl rule number %s'%(cpu_usage,index+1))
                time.sleep(1)
        cpu_usage2 = self.get_system_cpu_usage()
        log.info('system cpu usage before flows added = %f, after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))

    def test_scale_adding_igmp_acl_and_flow_entries_and_simultaneously_toggling_app_activation(self,igmp_groups=1300, flows_count=10000):
        cpu_usage1 = self.get_system_cpu_usage()
        def adding_igmp_entries():
            OnosCtrl(self.igmp_app).activate()
            groups = self.generate_random_multicast_ip_addresses(count = igmp_groups)
            sources = self.generate_random_unicast_ip_addresses(count = igmp_groups)
            self.onos_ssm_table_load(groups,src_list=sources,flag=True)
            for index in range(igmp_groups):
                self.send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                          iface = self.V_INF1)
                status = self.verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                assert_equal(status, True)
                log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
        def adding_flow_entries():
            egress = 1
            ingress = 2
            egress_mac = '00:00:00:00:01:01'
            ingress_mac = '02:00:00:00:00:00'
            for index in range(flows_count):
                ingress_mac = self.next_mac(ingress_mac)
                flow = OnosFlowCtrl(deviceId = self.device_id,
                        egressPort = egress + self.port_offset,
                        ingressPort = ingress + self.port_offset,
                        ethSrc = ingress_mac,
                        ethDst = egress_mac)
                result = flow.addFlow()
                assert_equal(result, True)
                log.info("flow number = %d is added",index+1)
        def adding_acl_entries():
            OnosCtrl(self.acl_app).activate()
            for index in range(flows_count):
                src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                dst_port = random.randint(1024,65535)
                log.info('adding acl rule = %d with src ip = %s, dst ip = %s and dst tcp port = %d'%(index+1, src_ip,dst_ip,dst_port))
                status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip, ipProto ='TCP', dstTpPort =dst_port, action = 'deny')
                assert_equal(status, True)
        igmp_thread  = threading.Thread(target = adding_igmp_entries)
        flows_thread  = threading.Thread(target = adding_flow_entries)
        acl_thread  = threading.Thread(target = adding_acl_entries)
        igmp_thread.start()
        flows_thread.start()
        acl_thread.start()
        time.sleep(1)
        igmp_thread.join()
        flows_thread.join()
        acl_thread.join()
        cpu_usage2 = self.get_system_cpu_usage()
        OnosCtrl(self.igmp_app).deactivate()
        OnosCtrl(self.acl_app).deactivate()
        cpu_usage3 = self.get_system_cpu_usage()
        log.info('cpu usage before test start = %f, after igmp,flow and acl entries loaded = %f and after the apps deactivated = %f'%(cpu_usage1,cpu_usage2,cpu_usage3))
        OnosCtrl(self.igmp_app).activate()
        OnosCtrl(self.acl_app).activate()

    def test_scale_for_vrouter_with_10000_routes(self):
        res = self.__vrouter_network_verify(10000, peers = 1)
        assert_equal(res, True)

    def test_scale_for_vrouter_with_20000_routes(self):
        res = self.__vrouter_network_verify(20000, peers = 2)
        assert_equal(res, True)

    def test_scale_for_vrouter_with_20000_routes(self):
        res = self.__vrouter_network_verify(20000, peers = 100)
        assert_equal(res, True)

    #simulating authentication for multiple users, 5K in this test case
    @deferred(TEST_TIMEOUT+1800)
    def test_scale_of_eap_tls_with_5k_sessions_using_diff_mac(self):
        df = defer.Deferred()
        def eap_tls_5k_with_diff_mac(df):
            for i in xrange(5000):
                tls = TLSAuthTest(src_mac = 'random')
                tls.runTest()
                log_test.info('Authentication successfull for user %d'%i)
            df.callback(0)
        reactor.callLater(0, eap_tls_5k_with_diff_mac, df)
        return df
