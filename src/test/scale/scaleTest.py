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
from nose.tools import *
from twisted.internet import defer
from nose.twistedtools import reactor, deferred
from CordTestUtils import *
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from SSHTestAgent import SSHTestAgent
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
        cls.setUpCordApi()
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
        subId = ''
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
            return subId

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

    def test_scale_for_cord_subscriber_creation_and_deletion(self):
        subId = self.vsg_xos_subscriber_create(100)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(100, subId)

    def test_cord_for_scale_of_subscriber_containers_per_compute_node(self):
        pass

