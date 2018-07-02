
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


import os
from nose.tools import *
from scapy.all import *
import requests
from twisted.internet import defer
from nose.twistedtools import reactor, deferred
from CordTestUtils import *
from CordTestUtils import log_test as log
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from SSHTestAgent import SSHTestAgent
from Channels import Channels, IgmpChannel
from IGMP import *
import time, monotonic
from CordLogger import CordLogger
from VSGAccess import VSGAccess
#imports for cord-subscriber module
from subscriberDb import SubscriberDB
from Stats import Stats
from threadPool import ThreadPool
import threading
from EapTLS import TLSAuthTest
from CordTestUtils import log_test as log
from CordTestConfig import setup_module, running_on_ciab
from OnosCtrl import OnosCtrl
from CordContainer import Onos
from CordSubscriberUtils import CordSubscriberUtils, XosUtils
from CordTestServer import cord_test_onos_restart, cord_test_quagga_restart, cord_test_shell, cord_test_radius_restart


log.setLevel('INFO')

class Subscriber(Channels):
      log.info('in Subscriber class 0000000')
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

            log_test.info('Subscriber %s, rx interface %s, uplink interface %s' %(name, self.rx_intf, self.tx_intf))
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

      def channel_join_next(self, delay = 2, leave_flag = True):
            '''Joins the next channel leaving the last channel'''
            if self.last_chan:
                  if self.join_map.has_key(self.last_chan):
                        del self.join_map[self.last_chan]
            self.delay = delay
            chan, join_time = self.join_next(leave_flag = leave_flag)
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

      def channel_leave(self, chan = 0, force = False):
            if self.join_map.has_key(chan):
                  del self.join_map[chan]
            self.leave(chan, force = force)

      def channel_update(self, chan, stats_type, packets, t=0):
            if type(chan) == type(0):
                  chan_list = (chan,)
            else:
                  chan_list = chan
            for c in chan_list:
                  if self.join_map.has_key(c):
                        self.join_map[c][stats_type].update(packets = packets, t = t)
      def channel_receive(self, chan, cb = None, count = 1, timeout = 5):
            log_test.info('Subscriber %s on port %s receiving from group %s, channel %d' %
                     (self.name, self.rx_intf, self.gaddr(chan), chan))
            r = self.recv(chan, cb = cb, count = count, timeout = timeout)
            if len(r) == 0:
                  log_test.info('Subscriber %s on port %s timed out' %(self.name, self.rx_intf))
            else:
                  log_test.info('Subscriber %s on port %s received %d packets' %(self.name, self.rx_intf, len(r)))
            if self.recv_timeout:
                  ##Negative test case is disabled for now
                  assert_equal(len(r), 0)

      def recv_channel_cb(self, pkt):
            ##First verify that we have received the packet for the joined instance
            log_test.info('Packet received for group %s, subscriber %s, port %s' %
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
            log_test.debug('Packet received in %.3f usecs for group %s after join' %(delta, pkt[IP].dst))

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
                           log_test.info('This service is failed and other services will not run for this subscriber')
                           break
            log_test.info('This Subscriber is tested for multiple service eligibility ')
            self.test_status = True

class scale(object):

    USER = "vagrant"
    PASS = "vagrant"
    head_node = os.getenv('HEAD_NODE', 'prod')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    MAX_PORTS = 100
    device_id = 'of:' + get_mac()
    test_path = os.path.dirname(os.path.realpath(__file__))
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config.json'))
    olt = OltConfig(olt_conf_file = olt_conf_file)
    APP_NAME = 'org.ciena.xconnect'
    olt_apps = ()
    table_app = 'org.ciena.cordigmp'
    table_app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-multitable-2.0-SNAPSHOT.oar')
    app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-2.0-SNAPSHOT.oar')
    cpqd_path = os.path.join(test_path, '..', 'setup')
    ovs_path = cpqd_path
    test_services = ('IGMP', 'TRAFFIC')
    num_joins = 0
    num_subscribers = 0
    leave_flag = True
    recv_timeout = False
    onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))
    PORT_TX_DEFAULT = 2
    PORT_RX_DEFAULT = 1
    IP_DST = '224.0.0.22'
    IGMP_DST_MAC = "01:00:5e:00:00:16"
    igmp_eth = Ether(dst = IGMP_DST_MAC, type = ETH_P_IP)
    igmp_ip = IP(dst = IP_DST)
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

############ IGMP utility functions #######################
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

    def generate_random_unicast_ip_addresses(self,count=1):
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
##################### acl utility functions ###############################

    @classmethod
    def acl_hosts_add(cls, dstHostIpMac, egress_iface_count = 1,  egress_iface_num = None):
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
        if egress_iface_num is None:
           egress_iface_num = cls.egress_iface
        n = 0
        for n in range(egress_iface_count):
           egress = cls.port_map[egress_iface_num]
           config_cmds_egress = ('ifconfig {} 0'.format(egress))
           os.system(config_cmds_egress)
           egress_iface_num += 1
    def acl_rule_traffic_send_recv(self, srcMac, dstMac, srcIp, dstIp, ingress =None, egress=None, ip_proto=None, dstPortNum = None, positive_test = True):
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



############################# vrouter utility functiuons ####################
    @classmethod
    def vrouter_setup(cls):
        apps = ('org.onosproject.proxyarp', 'org.onosproject.hostprovider', 'org.onosproject.vrouter', 'org.onosproject.fwd')
        for app in apps:
            OnosCtrl(app).activate()
        cls.port_map, cls.port_list = cls.olt.olt_port_map()
        cls.vrouter_device_dict = { "devices" : {
                "{}".format(cls.device_id) : {
                    "basic" : {
                        "driver" : "softrouter"
                    }
                }
             },
          }
        cls.zebra_conf = '''
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
    def vrouter_host_load(cls, peer_address = None):
        index = 1
        peer_info = peer_address if peer_address is not None else cls.peer_list

        for host,_ in peer_info:
            iface = cls.port_map[index]
            index += 1
            log_test.info('Assigning ip %s to interface %s' %(host, iface))
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
    def vrouter_config_get(cls, networks = 4, peers = 1, peer_address = None,
                           route_update = None, router_address = None):
        vrouter_configs = cls.generate_vrouter_conf(networks = networks, peers = peers,
                                                    peer_address = peer_address, router_address = router_address)
        return vrouter_configs

    @classmethod
    def vrouter_configure(cls, networks = 4, peers = 1, peer_address = None,
                          route_update = None, router_address = None, time_expire = None, adding_new_routes = None):
        vrouter_configs = cls.vrouter_config_get(networks = networks, peers = peers,
                                                 peer_address = peer_address, route_update = route_update)
        cls.start_onos(network_cfg = vrouter_configs)
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
                log_test.info('Pkt seen with ingress ip %s, egress ip %s' %(pkt[IP].src, pkt[IP].dst))
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
                                 deactivate_activate_vrouter = None, adding_new_routes = None):
	print 'no.of networks are.....', networks
        self.vrouter_setup()
        _, ports_map, egress_map = self.vrouter_configure(networks = networks, peers = peers,
                                                          peer_address = start_peer_address,
                                                          route_update = route_update,
                                                          router_address = start_network,
                                                          time_expire = time_expire,
                                                          adding_new_routes = adding_new_routes)
        self.vrouter_traffic_verify()
        self.vrouter_host_unload()
        return True

############### Cord Subscriber utility functions #########################

    @classmethod
    def flows_setup(cls):
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = cls.default_port_map
        cls.device_id = OnosCtrl.get_device_id()
        num_ports = len(cls.port_map['ports'] + cls.port_map['relay_ports'])
        cls.port_offset = int(os.getenv('TEST_INSTANCE', 0)) * num_ports

    @classmethod
    def update_apps_version(cls):
            version = Onos.getVersion()
            major = int(version.split('.')[0])
            minor = int(version.split('.')[1])
            cordigmp_app_version = '2.0-SNAPSHOT'
            olt_app_version = '1.2-SNAPSHOT'
            if major > 1:
                  cordigmp_app_version = '3.0-SNAPSHOT'
                  olt_app_version = '2.0-SNAPSHOT'
            elif major == 1:
                  if minor > 10:
                        cordigmp_app_version = '3.0-SNAPSHOT'
                        olt_app_version = '2.0-SNAPSHOT'
                  elif minor <= 8:
                        olt_app_version = '1.1-SNAPSHOT'
            cls.app_file = os.path.join(cls.test_path, '..', 'apps/ciena-cordigmp-{}.oar'.format(cordigmp_app_version))
            cls.table_app_file = os.path.join(cls.test_path, '..', 'apps/ciena-cordigmp-multitable-{}.oar'.format(cordigmp_app_version))
            cls.olt_app_file = os.path.join(cls.test_path, '..', 'apps/olt-app-{}.oar'.format(olt_app_version))

    @classmethod
    def subscriber_setup(cls):
        log.info('in subscriber_setup function 000000000')
	cls.subscriber_apps = ('org.opencord.aaa', 'org.onosproject.dhcp')
        for app in cls.subscriber_apps:
            OnosCtrl(app).activate()
	cls.update_apps_version()
        #dids = OnosCtrl.get_device_ids()
        #device_map = {}
        #for did in dids:
        #      device_map[did] = { 'basic' : { 'driver' : 'voltha' } }
        #network_cfg = {}
        #network_cfg = { 'devices' : device_map }
        #Restart ONOS with cpqd driver config for OVS
        #cls.start_onos(network_cfg = network_cfg)
        cls.port_map, cls.port_list = cls.olt.olt_port_map()
        cls.switches = cls.port_map['switches']
        cls.num_ports = cls.port_map['num_ports']
        if cls.num_ports > 1:
              cls.num_ports -= 1 ##account for the tx port
        #Uninstall the existing app if any
        #OnosCtrl.uninstall_app(cls.table_app)
        #log_test.info('Installing the multi table app %s for subscriber test' %(cls.table_app_file))
        #OnosCtrl.install_app(cls.table_app_file)

    @classmethod
    def subscriber_teardown(cls):
        log.info('in subscriber_teardown function 000000000')
        apps = cls.olt_apps + cls.subscriber_apps #( cls.table_app,)
        for app in apps:
            OnosCtrl(app).deactivate()
        #cls.start_onos(network_cfg = {})
        #OnosCtrl.uninstall_app(cls.table_app)
        #log_test.info('Installing back the cord igmp app %s for subscriber test on exit' %(cls.app_file))
        #OnosCtrl.install_app(cls.app_file)

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
            log.info('executing ovs_cleanup function 000000000000000000')
            ##For every test case, delete all the OVS groups
            cmd = 'ovs-ofctl del-groups br-int -OOpenFlow11 >/dev/null 2>&1'
            try:
                  cord_test_shell(cmd)
                  ##Since olt config is used for this test, we just fire a careless local cmd as well
                  os.system(cmd)
            finally:
                  return
    def tls_verify(self, subscriber):
            def tls_fail_cb():
                  log_test.info('TLS verification failed')
            if subscriber.has_service('TLS'):
                  #OnosCtrl('org.opencord.aaa').deactivate()
                  #time.sleep(2)
                  #OnosCtrl('org.opencord.aaa').activate()
                  #time.sleep(5)
                  tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = subscriber.rx_intf)
                  log_test.info('Running subscriber %s tls auth test' %subscriber.name)
                  tls.runTest()
                  assert_equal(tls.failTest, False)
                  self.test_status = True
                  return self.test_status
            else:
                  self.test_status = True
                  return self.test_status

    def generate_port_list(self, subscribers, channels):
            log.info('port list in generate port list is %s'%self.port_list)
            return self.port_list[:subscribers]
    def subscriber_load(self, create = True, num = 10, num_channels = 1, channel_start = 0, port_list = [], services = None):
          '''Load the subscriber from the database'''
          log.info('executing subscriber_load finction 000000000')
          test_services = services if services else self.test_services
          self.subscriber_db = SubscriberDB(create = create, services = test_services)
          if create is True:
                self.subscriber_db.generate(num)
          self.subscriber_info = self.subscriber_db.read(num)
          self.subscriber_list = []
          if not port_list:
                port_list = self.generate_port_list(num, num_channels)
          log.info('port_list in subscriber load is %s'%port_list)
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
          igmpChannel = IgmpChannel()
          ssm_groups = map(lambda sub: sub.channels, self.subscriber_list)
          ssm_list = reduce(lambda ssm1, ssm2: ssm1+ssm2, ssm_groups)
          igmpChannel.igmp_load_ssm_config(ssm_list)
    def subscriber_join_verify( self, num_subscribers = 10, num_channels = 1,
                                  channel_start = 0, cbs = None, port_list = [],
                                  services = None, negative_subscriber_auth = None):
        log.info('in subscriber_join_verify function 000000000')
        self.test_status = False
        self.ovs_cleanup()
        subscribers_count = num_subscribers
        sub_loop_count =  num_subscribers
        self.subscriber_load(create = True, num = num_subscribers,
                             num_channels = num_channels, channel_start = channel_start, port_list = port_list,
                             services = services)
        self.onos_aaa_config()
        self.thread_pool = ThreadPool(min(100, subscribers_count), queue_size=1, wait_timeout=1)
        chan_leave = False #for single channel, multiple subscribers
        if cbs is None:
              cbs = (self.tls_verify, self.dhcp_verify, self.igmp_verify, self.traffic_verify)
              chan_leave = True
        cbs_negative = cbs
        for subscriber in self.subscriber_list:
              if services and 'IGMP' in services:
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
              if services and 'IGMP' in services:
                 subscriber.stop()
              if chan_leave is True:
                    subscriber.channel_leave(0)
        subscribers_count = 0
        return self.test_status
    def tls_invalid_cert(self, subscriber):
          log.info('in tls_invalid_cert function 000000000000000')
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log_test.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT_INVALID)
             tls.runTest()
             if tls.failTest == True:
                self.test_status = False
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

    def tls_verify(self, subscriber):
            def tls_fail_cb():
                  log_test.info('TLS verification failed')
            if subscriber.has_service('TLS'):
                  tls = TLSAuthTest(fail_cb = tls_fail_cb, intf = subscriber.rx_intf)
                  log_test.info('Running subscriber %s tls auth test' %subscriber.name)
                  tls.runTest()
                  assert_equal(tls.failTest, False)
                  self.test_status = True
                  return self.test_status
            else:
                  self.test_status = True
                  return self.test_status

    def tls_non_ca_authrized_cert(self, subscriber):
          if subscriber.has_service('TLS'):
             time.sleep(2)
             log_test.info('Running subscriber %s tls auth test' %subscriber.name)
             tls = TLSAuthTest(client_cert = self.CLIENT_CERT_NON_CA_AUTHORIZED)
             tls.runTest()
             if tls.failTest == False:
                self.test_status = True
             return self.test_status
          else:
              self.test_status = True
              return self.test_status

    def dhcp_verify(self, subscriber):
            log.info('in dhcp_verify function 000000000000000')
            if subscriber.has_service('DHCP'):
                  cip, sip = self.dhcp_request(subscriber, update_seed = True)
                  log_test.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
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
                  log_test.info('Subscriber %s got client ip %s from server %s' %(subscriber.name, cip, sip))
                  subscriber.src_list = [cip]
                  self.test_status = True
                  return self.test_status
            else:
                  subscriber.src_list = ['10.10.10.{}'.format(subscriber.rx_port)]
                  self.test_status = True
                  return self.test_status

    def igmp_verify(self, subscriber):
            log.info('in igmp_verify function 000000000000000')
            chan = 0
            if subscriber.has_service('IGMP'):
                  ##We wait for all the subscribers to join before triggering leaves
                  if subscriber.rx_port > 1:
                        time.sleep(5)
                  subscriber.channel_join(chan, delay = 0)
                  self.num_joins += 1
                  while self.num_joins < self.num_subscribers:
                        time.sleep(5)
                  log_test.info('All subscribers have joined the channel')
                  for i in range(10):
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
                        log_test.info('Leaving channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_leave(chan)
                        time.sleep(5)
                        log_test.info('Interface %s Join RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name,subscriber.join_rx_stats))
                        #Should not receive packets for this subscriber
                        self.recv_timeout = True
                        subscriber.recv_timeout = True
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 10)
                        subscriber.recv_timeout = False
                        self.recv_timeout = False
                        log_test.info('Joining channel %d for subscriber %s' %(chan, subscriber.name))
                        subscriber.channel_join(chan, delay = 0)
                  self.test_status = True
                  return self.test_status

    def igmp_jump_verify(self, subscriber):
            if subscriber.has_service('IGMP'):
                  for i in xrange(subscriber.num):
                        log_test.info('Subscriber %s jumping channel' %subscriber.name)
                        chan = subscriber.channel_jump(delay=0)
                        subscriber.channel_receive(chan, cb = subscriber.recv_channel_cb, count = 1)
                        log_test.info('Verified receive for channel %d, subscriber %s' %(chan, subscriber.name))
                        time.sleep(3)
                  log_test.info('Interface %s Jump RX stats for subscriber %s, %s' %(subscriber.iface, subscriber.name, subscriber.join_rx_stats))
                  self.test_status = True
                  return self.test_status
    def traffic_verify(self, subscriber):
            if subscriber.has_service('TRAFFIC'):
                  url = 'http://www.google.com'
                  resp = requests.get(url)
                  self.test_status = resp.ok
                  if resp.ok == False:
                        log_test.info('Subscriber %s failed get from url %s with status code %d'
                                 %(subscriber.name, url, resp.status_code))
                  else:
                        log_test.info('GET request from %s succeeded for subscriber %s'
                                 %(url, subscriber.name))
                  return self.test_status
################## common utility functions #######################
    def get_system_cpu_usage(self):
        """ Getting compute node CPU usage """
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "top -b -n1 | grep 'Cpu(s)' | awk '{print $2 + $4}'"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        return float(output)

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
    def config_restore(cls):
        """Restore the vsg test configuration on test case failures"""
        for restore_method in cls.restore_methods:
            restore_method()

    def onos_aaa_config(self):
        OnosCtrl.aaa_load_config()

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log_test.info('Configure request for AAA returned status %d' %code)
            assert_equal(status, True)
            time.sleep(3)

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
