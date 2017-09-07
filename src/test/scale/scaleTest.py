
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
from Channels import Channels, IgmpChannel
from IGMP import *
from CordLogger import CordLogger
from VSGAccess import VSGAccess
from OnosFlowCtrl import OnosFlowCtrl
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
from Scale import scale
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
    NUM_SUBSCRIBERS = 16
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
    APP_NAME = 'org.ciena.xconnect'
    INTF_TX_DEFAULT = 'veth2'
    INTF_RX_DEFAULT = 'veth0'
    default_port_map = {
        PORT_TX_DEFAULT : INTF_TX_DEFAULT,
        PORT_RX_DEFAULT : INTF_RX_DEFAULT,
        INTF_TX_DEFAULT : PORT_TX_DEFAULT,
        INTF_RX_DEFAULT : PORT_RX_DEFAULT
        }
    vrouter_apps = ('org.onosproject.proxyarp', 'org.onosproject.hostprovider', 'org.onosproject.vrouter', 'org.onosproject.fwd')
    MAX_PORTS = 100
    subscriber_apps = ('org.opencord.aaa', 'org.onosproject.dhcp')
    olt_apps = () #'org.opencord.cordmcast')
    vtn_app = 'org.opencord.vtn'
    table_app = 'org.ciena.cordigmp'
    aaa_loaded = False
    table_app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-multitable-2.0-SNAPSHOT.oar')
    app_file = os.path.join(test_path, '..', 'apps/ciena-cordigmp-2.0-SNAPSHOT.oar')
    olt_app_file = os.path.join(test_path, '..', 'apps/olt-app-1.2-SNAPSHOT.oar')
    olt_app_name = 'org.onosproject.olt'
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    cpqd_path = os.path.join(test_path, '..', 'setup')
    ovs_path = cpqd_path
    test_services = ('IGMP', 'TRAFFIC')
    num_joins = 0
    num_subscribers = 0
    leave_flag = True
    num_channels = 0
    recv_timeout = False
    onos_restartable = bool(int(os.getenv('ONOS_RESTART', 0)))
    SUBSCRIBER_TIMEOUT = 300
    device_id = 'of:' + get_mac()

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
	log.info('in setUp class 00000000000000')
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

    @classmethod
    def tearDownClass(cls):
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.cord_subscriber.volt_subscriber_info)

    def log_set(self, level = None, app = 'org.onosproject'):
        CordLogger.logSet(level = level, app = app, controllers = self.controllers, forced = True)
######################## vsg - vcpe utility functions #########################
    @classmethod
    def closeVCPEAccess(cls, volt_subscriber_info):
        OnosCtrl.uninstall_app(cls.APP_NAME, onos_ip = cls.HEAD_NODE)

    @classmethod
    def openVCPEAccess(cls, volt_subscriber_info):
        """
        This code is used to configure leaf switch for head node access to compute node over fabric.
        Care is to be taken to avoid overwriting existing/default vcpe flows.
        The access is opened for generated subscriber info which should not overlap.
        We target the fabric onos instance on head node.
        """
        version = Onos.getVersion(onos_ip = cls.HEAD_NODE)
        app_version = '1.0-SNAPSHOT'
        major = int(version.split('.')[0])
        minor = int(version.split('.')[1])
        if major > 1:
            app_version = '2.0-SNAPSHOT'
        elif major == 1 and minor > 10:
            app_version = '2.0-SNAPSHOT'
        cls.APP_FILE = os.path.join(cls.test_path, '..', 'apps/xconnect-{}.oar'.format(app_version))
        OnosCtrl.install_app(cls.APP_FILE, onos_ip = cls.HEAD_NODE)
        time.sleep(2)
        s_tags = map(lambda tenant: int(tenant['voltTenant']['s_tag']), volt_subscriber_info)
        #only get unique vlan tags
        s_tags = list(set(s_tags))
        devices = OnosCtrl.get_device_ids(controller = cls.HEAD_NODE)
        if devices:
            device_config = {}
            for device in devices:
                device_config[device] = []
                for s_tag in s_tags:
                    xconnect_config = {'vlan': s_tag, 'ports' : [ cls.FABRIC_PORT_HEAD_NODE, cls.FABRIC_PORT_COMPUTE_NODE ] }
                    device_config[device].append(xconnect_config)

            cfg = { 'apps' : { 'org.ciena.xconnect' : { 'xconnectTestConfig' : device_config } } }
            OnosCtrl.config(cfg, controller = cls.HEAD_NODE)

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
            #log.info('Testing for external connectivity to VCPE %s' %(vcpe))
            #self.vsg_for_external_connectivity(index)

        return subId

    def vsg_delete(self, num_subscribers):
        if self.on_pod is False:
            return
        num_subscribers = min(num_subscribers, len(self.cord_subscriber.subscriber_info))
        for index in xrange(num_subscribers):
            subId = self.vsg_xos_subscriber_id(index)
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)

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

    def vsg_xos_subscriber_create_reserved(self):
        if self.on_pod is False:
            return
        tags_reserved = [ (int(vcpe['s_tag']), int(vcpe['c_tag'])) for vcpe in self.vcpes_reserved ]
        volt_tenants = self.restApiXos.ApiGet('TENANT_VOLT')
        subscribers = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        reserved_tenants = filter(lambda tenant: (int(tenant['s_tag']), int(tenant['c_tag'])) in tags_reserved, volt_tenants)
        reserved_config = []
        for tenant in reserved_tenants:
            for subscriber in subscribers:
                if int(subscriber['id']) == int(tenant['subscriber']):
                    volt_subscriber_info = {}
                    volt_subscriber_info['voltTenant'] = dict(s_tag = tenant['s_tag'],
                                                              c_tag = tenant['c_tag'],
                                                              subscriber = tenant['subscriber'])
                    volt_subscriber_info['volt_id'] = tenant['id']
                    volt_subscriber_info['account_num'] = subscriber['identity']['account_num']
                    reserved_config.append( (subscriber, volt_subscriber_info) )
                    break
            else:
                log.info('Subscriber not found for tenant %s, s_tag: %s, c_tag: %s' %(str(tenant['subscriber']),
                                                                                      str(tenant['s_tag']),
                                                                                      str(tenant['c_tag'])))

        for subscriber_info, volt_subscriber_info in reserved_config:
            self.vsg_xos_subscriber_delete(0,
                                           subId = str(subscriber_info['id']),
                                           voltId = str(volt_subscriber_info['volt_id']),
                                           subscriber_info = subscriber_info,
                                           volt_subscriber_info = volt_subscriber_info)
            subId = self.vsg_xos_subscriber_create(0,
                                                   subscriber_info = subscriber_info,
                                                   volt_subscriber_info = volt_subscriber_info)
            log.info('Created reserved subscriber %s' %(subId))

    @deferred(1800)
    def test_scale_for_vsg_vm_creations(self):
	try:
	    df = defer.Deferred()
	    def scale_vsg_vms(df):
        	for index in xrange(len(self.cord_subscriber.subscriber_info)):
                    #check if the index exists
                    subId = self.vsg_xos_subscriber_id(index)
                    log.info('test_vsg_xos_subscriber_creation - subId is %s'%subId)
                    if subId and subId != '0':
                        self.vsg_xos_subscriber_delete(index, subId = subId)
                    subId = self.vsg_xos_subscriber_create(index)
                    log.info('Created Subscriber %s' %(subId))
                df.callback(0)
            reactor.callLater(0, scale_vsg_vms, df)
            return df
	finally:
	    pass
	    #self.vsg_delete(len(self.cord_subscriber.subscriber_info))
	    self.vsg_xos_subscriber_create_reserved

    @deferred(1800)
    def test_scale_for_vcpe_creations(self):
        try:
            df = defer.Deferred()
            def scale_vcpe_instances(df):
                for index in xrange(len(self.cord_subscriber.subscriber_info)):
                    #check if the index exists
                    subId = self.vsg_xos_subscriber_id(index)
                    log.info('test_vsg_xos_subscriber_creation')
                    if subId and subId != '0':
                        self.vsg_xos_subscriber_delete(index, subId = subId)
                    subId = self.vsg_xos_subscriber_create(index)
                    log.info('Created Subscriber %s' %(subId))
                    df.callback(0)
            reactor.callLater(0, scale_vcpe_instances, df)
            return df
        except:
            self.vsg_delete(len(self.cord_subscriber.subscriber_info))
            self.vsg_xos_subscriber_create_reserved

    @deferred(1800)
    def test_scale_of_subcriber_vcpe_creations_in_single_vsg_vm(self):
	try:
            df = defer.Deferred()
            def scale_vcpe_instances(df):
                subId = self.vsg_xos_subscriber_create(100)
                if subId and subId != '0':
                   self.vsg_xos_subscriber_delete(100, subId)
                df.callback(0)
            reactor.callLater(0, scale_vsg_vms, df)
            return df
        except:
            self.vsg_delete(len(self.cord_subscriber.subscriber_info))
            self.vsg_xos_subscriber_create_reserved

    @deferred(1800)
    def test_scale_of_subcriber_vcpe_creations_in_multiple_vsg_vm(self):
        try:
            df = defer.Deferred()
            def scale_vcpe_instances(df):
                subId = self.vsg_xos_subscriber_create(100)
                if subId and subId != '0':
                    self.vsg_xos_subscriber_delete(100, subId)
                df.callback(0)
            reactor.callLater(0, scale_vsg_vms, df)
            return df
        except:
            self.vsg_delete(len(self.cord_subscriber.subscriber_info))
            self.vsg_xos_subscriber_create_reserved

    @deferred(1800)
    def test_scale_of_subcriber_vcpe_creations_with_one_vcpe_in_one_vsg_vm(self):
        try:
            df = defer.Deferred()
            def scale_vcpe_instances(df):
                subId = self.vsg_xos_subscriber_create(100)
                if subId and subId != '0':
                    self.vsg_xos_subscriber_delete(100, subId)
                df.callback(0)
            reactor.callLater(0, scale_vsg_vms, df)
            return df
        except:
            self.vsg_delete(len(self.cord_subscriber.subscriber_info))
            self.vsg_xos_subscriber_create_reserved

    @deferred(1800)
    def test_scale_for_cord_subscriber_creation_and_deletion(self):
        try:
            df = defer.Deferred()
            def scale_vcpe_instances(df):
                subId = self.vsg_xos_subscriber_create(100)
                if subId and subId != '0':
                    self.vsg_xos_subscriber_delete(100, subId)
                df.callback(0)
            reactor.callLater(0, scale_vsg_vms, df)
            return df
        except:
            self.vsg_delete(len(self.cord_subscriber.subscriber_info))
            self.vsg_xos_subscriber_create_reserved

    def test_cord_for_scale_of_subscriber_containers_per_compute_node(self):
        pass

    @deferred(10)
    def test_latency_of_cord_for_control_packets_using_icmp_packet(self):
        """
	Test-Method:
	1. Ping from cord-tester to wan interface IP of CiaB setup
	2. Grep latency of ping packets
	"""
        df = defer.Deferred()
        def scale_vcpe_instances(df):
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
            df.callback(0)
        reactor.callLater(0, scale_vsg_vms, df)
        return df

    @deferred(20)
    def test_latency_of_cord_for_control_packets_using_increasing_sizes_of_icmp_packet(self):
        """
	Test-Method:
	1. Ping from cord-tester to wan interface IP of CiaB setup
	2. Grep the latency of ping packet
	3. Repeat the process for varying sizes of ping packets
	"""
        df = defer.Deferred()
        def scale_vcpe_instances(df):
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
            df.callback(0)
        reactor.callLater(0, scale_vsg_vms, df)
        return df

    @deferred(10)
    def test_latency_of_cord_with_traceroute(self):
        """
	Test-Method:
	1. Traceroute from cord-tester to wan interface IP of CiaB setup
	2. Grep the latency of ping packet
	3. Repeat the process for varying sizes of ping packets
	"""
        df = defer.Deferred()
        def scale_vcpe_instances(df):
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
            assert_not_equal(latency,None)
            df.callback(0)
        reactor.callLater(0, scale_vsg_vms, df)
        return df

    #tested with 50 igmp joins on CiaB setup
    @deferred(1000)
    def test_scale_with_igmp_joins_for_multicast_groups_validating_cpu_usage(self, group_count=500):
        """
	Test-Method:
	1. Register 500 (group count is number to test) igmp groups in onos
	2. Send  igmp joins for registered groups
	3. Send multicast traffic to all registered groups
	4. Verify traffic forwards properly
	"""
        df = defer.Deferred()
        def scale_igmp_joins(df):
            OnosCtrl(self.igmp_app).activate()
            groups = scale().generate_random_multicast_ip_addresses(count = group_count)
            sources = scale().generate_random_unicast_ip_addresses(count = group_count)
            scale().onos_ssm_table_load(groups,src_list=sources,flag=True)
	    try:
                for index in range(group_count):
                    scale().send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
                    status = scale().verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                    assert_equal(status, True)
                    log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
	    except Exception as error:
		log.info('Got unexpected error %s'%error)
		raise
            df.callback(0)
        reactor.callLater(0, scale_igmp_joins, df)
        return df

    #tested with 50 igmp joins on CiaB setup
    @deferred(1000)
    def test_scale_with_igmp_joins_for_multicast_groups_toggling_igmp_app(self, group_count=1000):
	"""
	Test-Method:
	1. Register 1000 (group_count is a number to test, can increase the number)igmp groups in onos
	2. Send  igmp joins for registered groups
	3. Send multicast traffic to all registered groups
	4. Verify traffic forwards properly
	5. deactivate and activate igmp app in onos
	6. Verify multicast traffic do not forward after igmp app deactivated
	"""
        df = defer.Deferred()
        def scale_igmp_joins(df):
            OnosCtrl(self.igmp_app).activate()
            groups = scale().generate_random_multicast_ip_addresses(count = group_count)
            sources = scale().generate_random_unicast_ip_addresses(count = group_count)
            scale().onos_ssm_table_load(groups,src_list=sources,flag=True)
	    try:
                for index in range(group_count):
                    scale().send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
                    status = scale().verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                    assert_equal(status, True)
                    log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
		log_test.info('Deactivating igmp app in onos')
		OnosCtrl(self.igmp_app).deactivate()
		time.sleep(2)
		for index in range(group_count):
                    status = scale().verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                    assert_equal(status, False)
		    log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
		OnosCtrl(self.igmp_app).activate()
	    except Exception as error:
		log.info('Got unexpected error %s'%error)
		OnosCtrl(self.igmp_app).activate()
		raise
            df.callback(0)
        reactor.callLater(0, scale_igmp_joins, df)
        return df

    #tested with 50 igmp joins on CiaB setup
    @deferred(1800)
    def test_scale_with_igmp_joins_for_multicast_groups_validating_cpu_usage(self, group_count=2000):
	"""
	Test-Method:
	1. Register (group count value to test) igmp groups in onos
	2. Send  igmp joins for registered groups
	3. Send multicast traffic to all registered groups
	4. Verify traffic forwards properly
	"""
        df = defer.Deferred()
        def scale_igmp_joins(df):
            OnosCtrl(self.igmp_app).activate()
            groups = scale().generate_random_multicast_ip_addresses(count = group_count)
            sources = scale().generate_random_unicast_ip_addresses(count = group_count)
            scale().onos_ssm_table_load(groups,src_list=sources,flag=True)
	    try:
                for index in range(group_count):
                    scale().send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
                    status = scale().verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                    assert_equal(status, True)
                    log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
                    if index % 50 == 0:
                        cpu_usage = scale().get_system_cpu_usage()
                        log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, scale_igmp_joins, df)
        return df

    #tested with 50 igmp joins on CiaB setup
    @deferred(1000)
    def test_scale_of_igmp_joins_for_multicast_groups_validating_cpu_usage_after_app_deactivation_and_activation(self,group_count=2000):
	"""
	Test-Method:
	1. Register 2000 (Number to test) igmp groups in onos
	2. Send  igmp joins for registered groups
	3. Send multicast traffic to all registered groups
	4. Verify traffic forwards properly
	"""
        df = defer.Deferred()
        def scale_igmp_joins(df):
	    cpu_usage1 = scale().get_system_cpu_usage()
            OnosCtrl(self.igmp_app).activate()
            groups = scale().generate_random_multicast_ip_addresses(count = group_count)
            sources = scale().generate_random_unicast_ip_addresses(count = group_count)
            scale().onos_ssm_table_load(groups,src_list=sources,flag=True)
	    try:
                for index in range(group_count):
                    scale().send_igmp_join(groups = [groups[index]], src_list = [sources[index]],record_type = IGMP_V3_GR_TYPE_INCLUDE,
                                         iface = self.V_INF1)
                    status = scale().verify_igmp_data_traffic(groups[index],intf=self.V_INF1,source=sources[index])
                    assert_equal(status, True)
                    log_test.info('data received for group %s from source %s - %d'%(groups[index],sources[index],index))
                    if index % 50 == 0:
                        cpu_usage = self.get_system_cpu_usage()
                        log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
		cpu_usage2 = scale().get_system_cpu_usage()
                OnosCtrl(self.igmp_app).deactivate()
                time.sleep(2)
                cpu_usage3 = scale().get_system_cpu_usage()
                log.info('CPU usage before test start = %f after %d igmp entries registered in onos = %f and after the app deactivated = %f are'%(cpu_usage1,cpu_usage2,cpu_usage3))
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, scale_igmp_joins, df)
        return df

    #tested with 100 flow entries on CiaB setup
    @deferred(1000)
    def test_scale_adding_large_number_of_flow_entries_for_tcp_ports(self,count=1000):
	"""
	Test-Method:
	1. Add 1000 (Large number to test) flow entries with varying tcp port number in onos
	2. Send data traffic for added tcp port numbers
	3. Verify onos forwards data traffic properly
	"""
	scale().flows_setup()
        df = defer.Deferred()
        def scale_flow_entries(df):
            egress = 1
            ingress = 2
            egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'tcp_port': random.randint(1024,65535) }
            ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'tcp_port': random.randint(1024,65535) }
	    try:
                for index in range(0,count):
                    ingress_map['tcp_port'] = random.randint(1024,65535)
                    egress_map['tcp_port'] = random.randint(1024,65535)
		    src_port = ingress_map['tcp_port']
		    egr_port = egress_map['tcp_port']
		    #log.info('ingress port is %d and egress port is %d'%(src_port,egr_port))
                    flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + scale().port_offset,
                                ingressPort = ingress + scale().port_offset,
                                tcpSrc = ingress_map['tcp_port'],
                                tcpDst = egress_map['tcp_port']
                                )
                    result = flow.addFlow()
                    assert_equal(result, True)
                    log_test.info("flow number = %d is added",index+1)
                    def mac_recv_task():
                        def recv_cb(pkt):
                            log_test.info('Pkt seen with ingress TCP port %s, egress TCP port %s' %(pkt[TCP].sport, pkt[TCP].dport))
                            result = True
                        sniff(count=2, timeout=5,
                                      lfilter = lambda p: TCP in p and p[TCP].dport == egr_port and p[TCP].sport == src_port                                                         ,prn = recv_cb, iface = scale().port_map[egress])
                    t = threading.Thread(target = mac_recv_task)
                    t.start()
                    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
                    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
                    L4 = TCP(sport = src_port, dport = egr_port)
                    pkt = L2/L3/L4
                    log_test.info('Sending packets to verify if flows are correct')
                    sendp(pkt, count=50, iface = scale().port_map[ingress])
                    t.join()
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0,scale_flow_entries, df)
        return df

    #tested with 100 flow entries on CiaB setup
    @deferred(1000)
    def test_scale_adding_ip_flow_entries_validating_cpu_usage(self,count=5000):
	"""
	Test-Method:
	1. Add 5000(Edit count as per test requirement) flow entries with varying source and destination IP
	2. Send data traffic matching flow entries
	3. Verify onos forwards data traffic properly
	"""
	scale().flows_setup()
        df = defer.Deferred()
        def scale_flow_entries(df):
            cpu_usage1 = scale().get_system_cpu_usage()
            egress = 1
            ingress = 2
            egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '182.0.0.0' }
            ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.0.0.0' }
	    try:
                for index in range(0,count):
                    ingress_map['ip'] =  scale().generate_random_unicast_ip_addresses()[0] #next_ip(ingress_map['ip'])
                    assert_not_equal(ingress_map['ip'], None)
                    egress_map['ip'] =  scale().generate_random_unicast_ip_addresses()[0] #to_egress_ip(ingress_map['ip'])
                    flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + scale().port_offset,
                                ingressPort = ingress + scale().port_offset,
                                ethType = '0x0800',
                                ipSrc = ('IPV4_SRC', ingress_map['ip']+'/8'),
                                ipDst = ('IPV4_DST', egress_map['ip']+'/8')
                                )
                    if index % 50 == 0:
                        cpu_usage = scale().get_system_cpu_usage()
                        log.info('CPU usage is %s for flow number %d added'%(cpu_usage,index+1))
                        time.sleep(1)
                    def mac_recv_task():
                        def recv_cb(pkt):
                            log_test.info('Pkt seen with ingress source IP %s, destination IP %s' %(pkt[IP].src, pkt[IP].dst))
                            result = True
                        sniff(count=2, timeout=5,
                                      lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']                                                         ,prn = recv_cb, iface = scale().port_map[egress])
                    t = threading.Thread(target = mac_recv_task)
                    t.start()
                    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
                    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
                    pkt = L2/L3
                    log_test.info('Sending packets to verify if flows are correct')
                    sendp(pkt, count=50, iface = scale().port_map[ingress])
                    t.join()
                cpu_usage2 = scale().get_system_cpu_usage()
                log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, scale_flow_entries, df)
        return df

    #tested with 100 flow entries on CiaB setup
    @deferred(1000)
    def test_scale_adding_flow_entries_with_udp_ports(self,count=10000):
	"""
	Test-Method:
	1. Add 10000 (Number as per test requirement)flow entries with varying udp port number in onos
	2. Send data traffic matching flow entries
	3. Verify onos forwards data traffic properly
	"""
        scale().flows_setup()
        df = defer.Deferred()
        def scale_flow_entries(df):
            egress = 1
            ingress = 2
            egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1', 'udp_port': random.randint(1024,65535) }
            ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1', 'udp_port': random.randint(1024,65535) }
            try:
                for index in range(0,count):
                    ingress_map['udp_port'] = random.randint(1024,65535)
                    egress_map['udp_port'] = random.randint(1024,65535)
                    src_port = ingress_map['udp_port']
                    egr_port = egress_map['udp_port']
                    #log.info('ingress port is %d and egress port is %d'%(src_port,egr_port))
                    flow = OnosFlowCtrl(deviceId = self.device_id,
                                egressPort = egress + scale().port_offset,
                                ingressPort = ingress + scale().port_offset,
                                udpSrc = ingress_map['udp_port'],
                                udpDst = egress_map['udp_port']
                                )
                    result = flow.addFlow()
                    assert_equal(result, True)
                    log_test.info("flow number = %d is added",index+1)
                    def mac_recv_task():
                        def recv_cb(pkt):
                            log_test.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                            result = True
                        sniff(count=2, timeout=5,
                                      lfilter = lambda p: UDP in p and p[UDP].dport == egr_port and p[UDP].sport == src_port                                                         ,prn = recv_cb, iface = scale().port_map[egress])
                    t = threading.Thread(target = mac_recv_task)
                    t.start()
                    L2 = Ether(src = ingress_map['ether'], dst = egress_map['ether'])
                    L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
                    L4 = UDP(sport = src_port, dport = egr_port)
                    pkt = L2/L3/L4
                    log_test.info('Sending packets to verify if flows are correct')
                    sendp(pkt, count=50, iface = scale().port_map[ingress])
                    t.join()
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0,scale_flow_entries, df)
	return df

    #tested with 100 flow entries on CiaB setup
    @deferred(1000)
    def test_scale_adding_constant_destination_mac_flow_entries_validating_cpu_usage(self,count=100):
	"""
	Test-Method:
	1. Add 100(Change number as per requirement) flow entries with varying source mac
	2. Send data traffic matching flow entries
	3. Verify onos forwards data traffic properly
	"""
	scale().flows_setup()
        df = defer.Deferred()
        def scale_flow_entries(df):
            cpu_usage1 = self.get_system_cpu_usage()
            egress = 1
            ingress = 2
            egress_mac = '02:00:00:00:0:0'
            ingress_mac = '03:00:00:00:00:00'
	    try:
                for index in range(0,count):
		    result = False
                    ingress_mac = scale().next_mac(ingress_mac)
                    flow = OnosFlowCtrl(deviceId = self.device_id,
                        egressPort = egress + scale().port_offset,
                        ingressPort = ingress + scale().port_offset,
                        ethSrc = ingress_mac,
                        ethDst = egress_mac)
                    result = flow.addFlow()
                    assert_equal(result, True)
                    log.info("flow number = %d is added",index+1)
                    if index % 100 == 0:
                        cpu_usage = scale().get_system_cpu_usage()
                        log.info('CPU usage is %s for multicast group entries %s'%(cpu_usage,index+1))
                        time.sleep(1)
                    def mac_recv_task():
                        def recv_cb(pkt):
                            log_test.info('Pkt seen with ingress mac %s, egress mac %s' %(pkt.src , pkt.dst))
                            result = True
                        sniff(count=2, timeout=5,
                                      lfilter = lambda p: p.src == ingress_mac and p.dst == egress_mac                                                         ,prn = recv_cb, iface = scale().port_map[egress])
                    t = threading.Thread(target = mac_recv_task)
                    t.start()
                    L2 = Ether(src = ingress_mac, dst = egress_mac)
                    pkt = L2/IP()
                    log_test.info('Sending packets to verify if flows are correct')
                    sendp(pkt, count=50, iface = scale().port_map[ingress])
                    t.join()
		    assert_equal(result, True)
                cpu_usage2 = self.get_system_cpu_usage()
                log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0,scale_flow_entries, df)
        return df


    @deferred(1000)
    def test_scale_adding_acl_rules_to_deny_matching_destination_tcp_port_traffic(self,count=10000):
	"""
	Test-Method:
	1. Add 10000 (Adjust number as per test requirement)acl deny rules with varying tcp port number
	2. Send data traffic matching flow entries
	3. Verify onos drops data traffic properly
	"""
        df = defer.Deferred()
        def scale_acl_rules(df):
		    acl_rule = ACLTest()
		    ingress = self.ingress_iface
            egress = self.CURRENT_PORT_NUM
			status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
            self.CURRENT_PORT_NUM += 1
            time.sleep(5)
			assert_equal(status, True)
			srcMac = '00:00:00:00:00:11'
            dstMac = host_ip_mac[0][1]
            scale().acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
			try:
                for index in range(0,count):
				    status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
                    self.CURRENT_PORT_NUM += 1
                    src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_port = random.randint(1024,65535)
                    log.info('adding acl rule = %d with src ip = %s, dst ip = %s and dst tcp port = %d'%(index+1, src_ip,dst_ip,dst_port))
                    status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip, ipProto ='TCP', dstTpPort =dst_port, action = 'deny')
                    assert_equal(status, True)
					self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp = src_ip, dstIp = dst_ip,ingress =ingress, egress = egress, ip_proto = 'TCP',positive_test = False)
					scale().acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
		    except Exception as error:
                log.info('Got unexpected error %s'%error)
				self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
                raise
            df.callback(0)
        reactor.callLater(0, scale_vsg_vms, df)
        return df

    @deferred(1000)
    def test_scale_adding_acl_rules_to_allow_src_and_dst_ip_matching_traffic_validating_cpu_usage(self,count=10000):
	"""
	Test-Method:
	1. Grep system usage before starting test case
	2. Configure 10000(As per test requirement) acl rules in onos
	3. Verify traffic test for all 10000 acl rules configured
	4. Grep system usage again now
	"""
        df = defer.Deferred()
        def scale_acl_rules(df):
            cpu_usage1 = self.get_system_cpu_usage()
		    ingress = self.ingress_iface
            egress = self.CURRENT_PORT_NUM
			status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
            self.CURRENT_PORT_NUM += 1
            time.sleep(5)
			assert_equal(status, True)
			srcMac = '00:00:00:00:00:11'
            dstMac = host_ip_mac[0][1]
            self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
            acl_rule = ACLTest()
			try:
                for index in range(0,count):
				    status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
                    self.CURRENT_PORT_NUM += 1
                    src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_port = random.randint(1024,65535)
                    log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
                    status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'allow')
                    assert_equal(status, True)
					self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 456)
                    if index % 100 == 0:
                        cpu_usage = self.get_system_cpu_usage()
                        log.info('CPU usage is %s for acl rule number %s'%(cpu_usage,index+1))
                        time.sleep(1)
				    self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
			except Exception as error:
                log.info('Got unexpected error %s'%error)
				self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
                raise
            cpu_usage2 = self.get_system_cpu_usage()
            log.info('system cpu usage before flows added = %f and after %d flows added = %f'%(cpu_usage1,count,cpu_usage2))
            df.callback(0)
        reactor.callLater(0, scale_acl_rules, df)
        return df

    @deferred(1000)
    def test_scale_adding_and_deleting_acl_rules_to_allow_src_and_dst_ip_matching_traffic(self,count=10000):
        """
	Test-Method:
	1. Add 10000 (Number as per requirement)acl rules to allow source and destinaiton IP matching traffic
	2. Send acl rules matching traffic
	3. Delete all the added acl rules
	"""
        df = defer.Deferred()
        def scale_acl_rules(df):
		    ingress = self.ingress_iface
            egress = self.CURRENT_PORT_NUM
			status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
            self.CURRENT_PORT_NUM += 1
            time.sleep(5)
			assert_equal(status, True)
			srcMac = '00:00:00:00:00:11'
            dstMac = host_ip_mac[0][1]
            self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
            acl_rule = ACLTest()
			try:
                for index in range(0,count):
				    status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
                    self.CURRENT_PORT_NUM += 1
                    src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_port = random.randint(1024,65535)
                    log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
                    status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'allow')
                    assert_equal(status, True)
					self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 456)
                result = acl_rule.get_acl_rules()
                result = result.json()['aclRules']
                for acl in result:
                    acl_rule.remove_acl_rule(acl['id'])
                    log.info('removed acl with Id --> %s'%acl['id'])
				self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
			except Exception as error:
                log.info('Got unexpected error %s'%error)
				self.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)
                raise
            df.callback(0)
        reactor.callLater(0, scale_acl_rules, df)
        return df

    @deferred(1000)
    def test_scale_adding_acl_rules_to_deny_src_and_dst_ip_matching_traffic_toggling_acl_app(self,count=20000):
	"""
	Test-Method:
	1. Add 20000 (Number as test requirement)acl rules to allow source and destinaiton IP matching traffic
	2. Send acl rules matching traffic
	3. Verify onos drops the traffic as the rule is deny type
	4. Deactivate the acl app in onos
	4. Verify now onos forwards the traffic
	"""
        df = defer.Deferred()
        def scale_acl_rules(df):
		    ingress = self.ingress_iface
            egress = self.CURRENT_PORT_NUM
			status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
            self.CURRENT_PORT_NUM += 1
            time.sleep(5)
			assert_equal(status, True)
			srcMac = '00:00:00:00:00:11'
            dstMac = host_ip_mac[0][1]
            self.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
            acl_rule = ACLTest()
            try:
                for index in range(0,count):
				    status,code,host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.HOST_DST_IP)
                    self.CURRENT_PORT_NUM += 1
                    src_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_ip =  self.generate_random_unicast_ip_addresses(count=1)[0]+'/32'
                    dst_port = random.randint(1024,65535)
                    log.info('adding acl rule = %d with src ip = %s, dst ip = %s '%(index+1, src_ip,dst_ip))
                    status,code = acl_rule.adding_acl_rule('v4', srcIp=src_ip, dstIp = dst_ip,action = 'deny')
                    assert_equal(status, True)
					self.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.ACL_SRC_IP, dstIp = self.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', dstPortNum = 456)
                OnosCtrl(cls.acl_app).deactivate()
                time.sleep(3)
			except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
            df.callback(0)
        reactor.callLater(0, scale_acl_rules, df)
        return df

    @deferred(1000)
    def test_scale_adding_igmp_and_acl_with_flow_entries_and_check_cpu_usage(self,igmp_groups=1300, flows_count=10000):
	"""
	Test-Method:
	1. Add igmp and flow entries in onos
	2. Send igmp joins for corresponding igmp entries
	3. Send multicast data traffic to registered igmp groups
	3. Verify onos forwards the traffic
	4. Send traffic matching the flow entries
	4. Verify onos forwards the traffic
	"""
        df = defer.Deferred()
        def scale_igmp_acl_flows(df):
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
            df.callback(0)
        reactor.callLater(0, scale_igmp_acl_flows, df)
        return df

    @deferred(1000)
    def test_scale_adding_igmp_acl_and_flow_entries_and_simultaneously_toggling_app(self,igmp_groups=1300, flows_count=10000):
	"""
	Test-Method:
	1. Add igmp, acl and flow entries in onos
	2. Send igmp joins for corresponding igmp entries
	3. Send multicast data traffic to registered igmp groups
	3. Verify onos forwards the traffic
	4. Send traffic matching the flow entries
	4. Verify onos forwards the traffic
	5. Send traffic matching acl rules
	6. Verify onos forwards the traffic
	"""
        df = defer.Deferred()
        def scale_igmp_acl_flows(df):
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
            df.callback(0)
        reactor.callLater(0, scale_igmp_acl_flows, df)
        return df

    #tested with 100 routes on CiaB
    @deferred(1000)
    def test_scale_for_vrouter_with_large_number_of_routes_and_peers(self):
	"""
	Test-Method:
	1. Add 100000 routes with 100 pairs in quagga(Change scale test number as per test requirement)
	2. Verify routes pushed to onos  from quagga
	3. Send traffic destined  the routes added
	3. Verify onos forwards the traffic
	"""
        scale().vrouter_setup()
        df = defer.Deferred()
        def scale_vrouter_routes(df):
	    try:
                res = scale().vrouter_network_verify(10000, peers = 100)
                assert_equal(res, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		raise
            df.callback(0)
        reactor.callLater(0, scale_vrouter_routes, df)
        return df

    #tested with 100 subscribers on CiaB
    @deferred(1800)
    def test_scale_of_eap_tls_with_huge_number_of_sessions_using_diff_mac(self):
	"""
	Test-Method:
	1. Simulate eap authentication requests for 5000 users(Adjust user number as per requirement)
	2. Verify authentication is succes for all 5000 users
	"""
	OnosCtrl('org.opencord.aaa').activate()
        df = defer.Deferred()
        def eap_tls_5k_with_diff_mac(df):
	    try:
                for i in xrange(5000):
                    tls = TLSAuthTest(src_mac = 'random')
                    tls.runTest()
                    log_test.info('Authentication successfull for user %d'%i)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		raise
            df.callback(0)
        reactor.callLater(0, eap_tls_5k_with_diff_mac, df)
        return df

    #tested with 100 subscribers on CiaB
    @deferred(1800)
    def test_scale_of_eap_tls_with_huge_number_of_sessions_using_diff_mac_with_aaa_app_deactivation_and_activation(self):
	"""
	Test-Method:
	1. Simulate eap authentication requests for 5000 users(Adjust user number as per requirement)
	2. Verify authentication is succes for all 5000 users
	3. Deactivate and activate the aaa app in onos
	4. Simulate eap authentication requests for 5000 users
	5. Verify authentication is succes for all 5000 users
	"""
	OnosCtrl('org.opencord.aaa').activate()
	df = defer.Deferred()
        def eap_tls_5k_with_diff_mac(df):
	    try:
		for i in xrange(5000):
                    tls = TLSAuthTest(src_mac = 'random')
                    tls.runTest()
                    log_test.info('Authentication successfull for user %d'%i)
	        OnosCtrl('org.opencord.aaa').deactivate()
	        time.sleep(2)
	        OnosCtrl('org.opencord.aaa').activate()
                for i in xrange(100):
                    tls = TLSAuthTest(src_mac = 'random')
                    tls.runTest()
                    log_test.info('Authentication successfull for user %d'%i)
		OnosCtrl('org.opencord.aaa').activate()
            except Exception as error:
                log.info('Got Unexpected  error %s'%error)
		OnosCtrl('org.opencord.aaa').activate()
                raise
            df.callback(0)
        reactor.callLater(0, eap_tls_5k_with_diff_mac, df)
        return df

    #tested with 10 subscribers on CiaB
    @deferred(1800)
    def test_scale_for_cord_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing(self):
	"""
	Test-Method:
	1. Simulate 5000 subscribers to get authentication access(Adjust cord subscribers according to test)
	2. Send igmp joins from all the subcribers
	3. Verify multicast traffic received to all 5000 subscribers
	"""
	scale().subscriber_setup()
        df = defer.Deferred()
        def cordsub_auth_invalid_cert(df):
            num_subscribers = 2
            num_channels = 1
	    try:
                test_status = scale().subscriber_join_verify(num_subscribers = num_subscribers,
                                                        num_channels = num_channels,
                                                        cbs = (scale().tls_invalid_cert, scale().dhcp_verify, scale().igmp_verify),
                                                        port_list = scale().generate_port_list(num_subscribers, num_channels),                                                          negative_subscriber_auth = 'half')
                assert_equal(test_status, True)
            except Exception as error:
                log.info('Got Unexpected  error %s'%error)
		raise
	    finally:
                scale().subscriber_teardown()
            df.callback(0)
        reactor.callLater(0, cordsub_auth_invalid_cert, df)
        return df

    #tested with 10 subscribers on CiaB
    @deferred(1800)
    def test_scale_for_cord_subscribers_with_igmp_join_and_jump_for_multiple_channels(self):
	"""
        Test-Method:
        1. Simulate 5000 subscribers(Adjust number as per test)
        2. Send igmp joins from all the subcribers
        3. Verify multicast traffic received to all 5000 subscribers
        """
        scale().subscriber_setup()
        df = defer.Deferred()
        def cordsub_igmp_join_jump(df):
            num_subscribers = 5000
            num_channels = 1500
	    try:
	        test_status = scale().subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (scale().tls_verify, scale().dhcp_jump_verify, scale().igmp_jump_verify),
                                                    port_list = scale().generate_port_list(num_subscribers, num_channels),
                                                    negative_subscriber_auth = 'all')
                assert_equal(test_status, True)
            except Exception as error:
                log.info('Got Unexpected  error %s'%error)
		raise
            finally:
                scale().subscriber_teardown()
            df.callback(0)
        reactor.callLater(0, cordsub_igmp_join_jump, df)
	return df

    #tested with 10 subscribers on CiaB
    @deferred(1800)
    def test_scale_for_cord_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing(self):
	"""
        Test-Method:
        1. Simulate 10000 subscribers to get authentication access(Adjust number as per test)
        2. Send igmp joins from all the subcribers
        3. Verify multicast traffic received to all 10000 subscribers
        """
	scale().subscriber_setup()
        df = defer.Deferred()
        def cordsub_auth_valid_cert(df):
            num_subscribers = 10000
            num_channels = 1
	    try:
                test_status = scale().subscriber_join_verify(num_subscribers = num_subscribers,
                                                 num_channels = num_channels,
                                                 cbs = (scale().tls_non_ca_authrized_cert, scale().dhcp_verify, scale().igmp_verify),
                                                 port_list = scale().generate_port_list(num_subscribers, num_channels),
                                                 negative_subscriber_auth = 'onethird')
                assert_equal(test_status, True)
            except Exception as error:
                log.info('Got Unexpected  error %s'%error)
		raise
            finally:
                scale().subscriber_teardown()
            df.callback(0)
        reactor.callLater(0, cordsub_auth_valid_cert, df)
        return df
