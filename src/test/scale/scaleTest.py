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
    subscriber_account_num = 100
    subscriber_s_tag = 500
    subscriber_c_tag = 500
    subscribers_per_s_tag = 8
    subscriber_map = {}
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


    @classmethod
    def getSubscriberCredentials(cls, subId):
        """Generate our own account num, s_tag and c_tags"""
        if subId in cls.subscriber_map:
            return cls.subscriber_map[subId]
        account_num = cls.subscriber_account_num
        cls.subscriber_account_num += 1
        s_tag, c_tag = cls.subscriber_s_tag, cls.subscriber_c_tag
        cls.subscriber_c_tag += 1
        if cls.subscriber_c_tag % cls.subscribers_per_s_tag == 0:
            cls.subscriber_s_tag += 1
        cls.subscriber_map[subId] = account_num, s_tag, c_tag
        return cls.subscriber_map[subId]

    @classmethod
    def getXosCredentials(cls):
        onos_cfg = OnosCtrl.get_config()
        if onos_cfg is None:
            return None
        if 'apps' in onos_cfg and \
           'org.opencord.vtn' in onos_cfg['apps'] and \
           'cordvtn' in onos_cfg['apps']['org.opencord.vtn'] and \
           'xos' in onos_cfg['apps']['org.opencord.vtn']['cordvtn']:
            xos_cfg = onos_cfg['apps']['org.opencord.vtn']['cordvtn']['xos']
            endpoint = xos_cfg['endpoint']
            user = xos_cfg['user']
            password = xos_cfg['password']
            xos_endpoints = endpoint.split(':')
            xos_host = xos_endpoints[1][len('//'):]
            xos_port = xos_endpoints[2][:-1]
            #log.info('xos_host: %s, port: %s, user: %s, password: %s' %(xos_host, xos_port, user, password))
            return dict(host = xos_host, port = xos_port, user = user, password = password)

        return None

    @classmethod
    def getSubscriberConfig(cls, num_subscribers):
        features =  {
            'cdn': True,
            'uplink_speed': 1000000000,
            'downlink_speed': 1000000000,
            'uverse': True,
            'status': 'enabled'
        }
        subscriber_map = []
        for i in xrange(num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, _, _ = cls.getSubscriberCredentials(subId)
            identity = { 'account_num' : str(account_num),
                         'name' : 'My House {}'.format(i)
                         }
            sub_info = { 'features' : features,
                         'identity' : identity
                         }
            subscriber_map.append(sub_info)

        return subscriber_map

    @classmethod
    def getVoltSubscriberConfig(cls, num_subscribers):
        voltSubscriberMap = []
        for i in xrange(num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, s_tag, c_tag = cls.getSubscriberCredentials(subId)
            voltSubscriberInfo = {}
            voltSubscriberInfo['voltTenant'] = dict(s_tag = str(s_tag),
                                                    c_tag = str(c_tag),
                                                    subscriber = '')
            voltSubscriberInfo['account_num'] = account_num
            voltSubscriberMap.append(voltSubscriberInfo)

        return voltSubscriberMap

    @classmethod
    def setUpCordApi(cls):
        our_path = os.path.dirname(os.path.realpath(__file__))
        cord_api_path = os.path.join(our_path, '..', 'cord-api')
        framework_path = os.path.join(cord_api_path, 'Framework')
        utils_path = os.path.join(framework_path, 'utils')
        data_path = os.path.join(cord_api_path, 'Tests', 'data')
        subscriber_cfg = os.path.join(data_path, 'Subscriber.json')
        volt_tenant_cfg = os.path.join(data_path, 'VoltTenant.json')
        num_subscribers = max(cls.NUM_SUBSCRIBERS, 10)
        cls.subscriber_info = cls.getSubscriberConfig(num_subscribers)
        cls.volt_subscriber_info = cls.getVoltSubscriberConfig(num_subscribers)

        sys.path.append(utils_path)
        sys.path.append(framework_path)
        from restApi import restApi
        restApiXos = restApi()
        xos_credentials = cls.getXosCredentials()
        if xos_credentials is None:
            restApiXos.controllerIP = cls.HEAD_NODE
            restApiXos.controllerPort = '9000'
        else:
            restApiXos.controllerIP = xos_credentials['host']
            restApiXos.controllerPort = xos_credentials['port']
            restApiXos.user = xos_credentials['user']
            restApiXos.password = xos_credentials['password']
        cls.restApiXos = restApiXos

    @classmethod
    def getVoltId(cls, result, subId):
        if type(result) is not type([]):
            return None
        for tenant in result:
            if str(tenant['subscriber']) == str(subId):
                return str(tenant['id'])
        return None

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
        #cls.setUpCordApi()
        if cls.on_pod is True:
            cls.openVCPEAccess(cls.volt_subscriber_info)

    @classmethod
    def tearDownClass(cls):
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.volt_subscriber_info)

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

    def vsg_xos_subscriber_id(self, index):
	log.info('index and its type are %s, %s'%(index, type(index)))
        volt_subscriber_info = self.volt_subscriber_info[index]
        result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        assert_not_equal(result, None)
        subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
        return subId

    def vsg_xos_subscriber_create(self, index, subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return ''
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        log.info('Creating tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        """subId = ''
        try:
            result = self.restApiXos.ApiPost('TENANT_SUBSCRIBER', subscriber_info)
            assert_equal(result, True)
            result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
            assert_not_equal(subId, '0')
            log.info('Subscriber ID for account num %s = %s' %(str(volt_subscriber_info['account_num']), subId))
            volt_tenant = volt_subscriber_info['voltTenant']
            #update the subscriber id in the tenant info before making the rest
            volt_tenant['subscriber'] = subId
            result = self.restApiXos.ApiPost('TENANT_VOLT', volt_tenant)
            assert_equal(result, True)
            #if the vsg instance was already instantiated, then reduce delay
            if c_tag % self.subscribers_per_s_tag == 0:
                delay = 350
            else:
                delay = 90
            log.info('Delaying %d seconds for the VCPE to be provisioned' %(delay))
            time.sleep(delay)
            log.info('Testing for external connectivity to VCPE %s' %(vcpe))
            self.vsg_for_external_connectivity(index)
        finally:
            return subId"""

    def vsg_xos_subscriber_delete(self, index, subId = '', voltId = '', subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        log.info('Deleting tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        if not subId:
            #get the subscriber id first
            result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
            assert_not_equal(subId, '0')
        if not voltId:
            #get the volt id for the subscriber
            result = self.restApiXos.ApiGet('TENANT_VOLT')
            assert_not_equal(result, None)
            voltId = self.getVoltId(result, subId)
            assert_not_equal(voltId, None)
        log.info('Deleting subscriber ID %s for account num %s' %(subId, str(volt_subscriber_info['account_num'])))
        status = self.restApiXos.ApiDelete('TENANT_SUBSCRIBER', subId)
        assert_equal(status, True)
        #Delete the tenant
        log.info('Deleting VOLT Tenant ID %s for subscriber %s' %(voltId, subId))
        self.restApiXos.ApiDelete('TENANT_VOLT', voltId)

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

    def test_scale_for_vsg_vm_creations(self):
        for index in xrange(len(self.subscriber_info)):
            #check if the index exists
            subId = self.vsg_xos_subscriber_id(index)
            log.info('test_vsg_xos_subscriber_creation')
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)
            subId = self.vsg_xos_subscriber_create(index)
            log.info('Created Subscriber %s' %(subId))

    def test_scale_for_vcpe_creations(self):
        for index in xrange(len(self.subscriber_info)):
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

    def test_scale_igmp_joins_for_2000_multicast_groups_and_check_cpu_usage_after_app_deactivation_and_activation(self,group_count=500):
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

