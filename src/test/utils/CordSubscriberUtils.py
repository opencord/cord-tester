
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
import sys
import time
from nose.tools import *
from CordTestUtils import log_test as log
from OnosCtrl import OnosCtrl

class XosUtils(object):

    head_node = os.getenv('HEAD_NODE', 'head1')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    CONTROLLER_PORT = '9000'
    our_path = os.path.dirname(os.path.realpath(__file__))
    cord_api_path = os.path.join(our_path, '..', 'cord-api')
    framework_path = os.path.join(cord_api_path, 'Framework')
    utils_path = os.path.join(framework_path, 'utils')
    sys.path.append(utils_path)
    sys.path.append(framework_path)

    @classmethod
    def getCredentials(cls):
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
    def getRestApi(cls):
        try:
            from restApi import restApi
            restApiXos = restApi()
            xos_credentials = cls.getCredentials()
            if xos_credentials is None:
                restApiXos.controllerIP = cls.HEAD_NODE
                restApiXos.controllerPort = cls.CONTROLLER_PORT
            else:
                restApiXos.controllerIP = xos_credentials['host']
                restApiXos.controllerPort = xos_credentials['port']
                restApiXos.user = xos_credentials['user']
                restApiXos.password = xos_credentials['password']

            return restApiXos
        except:
            return None

    def __init__(self):
        self.restApi = self.getRestApi()

    def subscriberCreate(self, subscriber_info, volt_subscriber_info):
        subId = ''
        try:
            result = self.restApi.ApiPost('TENANT_SUBSCRIBER', subscriber_info)
            assert_equal(result, True)
            result = self.restApi.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApi.getSubscriberId(result, volt_subscriber_info['account_num'])
            assert_not_equal(subId, '0')
            log.info('Subscriber ID for account num %s = %s' %(str(volt_subscriber_info['account_num']), subId))
            volt_tenant = volt_subscriber_info['voltTenant']
            #update the subscriber id in the tenant info before making the rest
            volt_tenant['subscriber'] = subId
            result = self.restApi.ApiPost('TENANT_VOLT', volt_tenant)
            assert_equal(result, True)
        finally:
            return subId

    def subscriberDelete(self, account_num, subId = '', voltId = ''):
        if not subId:
            #get the subscriber id first
            result = self.restApi.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApi.getSubscriberId(result, account_num)
            assert_not_equal(subId, '0')
        if not voltId:
            #get the volt id for the subscriber
            result = self.restApi.ApiGet('TENANT_VOLT')
            assert_not_equal(result, None)
            voltId = CordSubscriberUtils.getVoltId(result, subId)
            assert_not_equal(voltId, None)
        log.info('Deleting subscriber ID %s for account num %s' %(subId, str(account_num)))
        status = self.restApi.ApiDelete('TENANT_SUBSCRIBER', subId)
        assert_equal(status, True)
        #Delete the tenant
        log.info('Deleting VOLT Tenant ID %s for subscriber %s' %(voltId, subId))
        self.restApi.ApiDelete('TENANT_VOLT', voltId)

    def subscriberId(self, account_num):
        result = self.restApi.ApiGet('TENANT_SUBSCRIBER')
        assert_not_equal(result, None)
        subId = self.restApi.getSubscriberId(result, account_num)
        return subId

class CordSubscriberUtils(object):

    SUBSCRIBER_ACCOUNT_NUM = 100
    SUBSCRIBER_S_TAG = 500
    SUBSCRIBER_C_TAG = 500
    SUBSCRIBERS_PER_S_TAG = 8

    def __init__(self,
                 num_subscribers,
                 account_num = SUBSCRIBER_ACCOUNT_NUM,
                 s_tag = SUBSCRIBER_S_TAG,
                 c_tag = SUBSCRIBER_C_TAG,
                 subscribers_per_s_tag = SUBSCRIBERS_PER_S_TAG):
        self.num_subscribers = num_subscribers
        self.account_num = account_num
        self.s_tag = s_tag
        self.c_tag = c_tag
        self.subscribers_per_s_tag = subscribers_per_s_tag
        self.subscriber_map = {}
        self.subscriber_info = self.getConfig()
        self.volt_subscriber_info = self.getVoltConfig()
        self.xos = XosUtils()

    def getCredentials(self, subId):
        """Generate our own account num, s_tag and c_tags"""
        if subId in self.subscriber_map:
            return self.subscriber_map[subId]
        account_num = self.account_num
        self.account_num += 1
        s_tag, c_tag = self.s_tag, self.c_tag
        self.c_tag += 1
        if self.c_tag % self.subscribers_per_s_tag == 0:
            self.s_tag += 1
        self.subscriber_map[subId] = account_num, s_tag, c_tag
        return self.subscriber_map[subId]

    def getConfig(self):
        features =  {
            'cdn': True,
            'uplink_speed': 1000000000,
            'downlink_speed': 1000000000,
            'uverse': True,
            'status': 'enabled'
        }
        subscriber_map = []
        for i in xrange(self.num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, _, _ = self.getCredentials(subId)
            identity = { 'account_num' : str(account_num),
                         'name' : 'My House {}'.format(i)
                         }
            sub_info = { 'features' : features,
                         'identity' : identity
                         }
            subscriber_map.append(sub_info)

        return subscriber_map

    def getVoltConfig(self):
        voltSubscriberMap = []
        for i in xrange(self.num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, s_tag, c_tag = self.getCredentials(subId)
            voltSubscriberInfo = {}
            voltSubscriberInfo['voltTenant'] = dict(s_tag = str(s_tag),
                                                    c_tag = str(c_tag),
                                                    subscriber = '')
            voltSubscriberInfo['account_num'] = account_num
            voltSubscriberMap.append(voltSubscriberInfo)

        return voltSubscriberMap

    @classmethod
    def getVoltId(cls, result, subId):
        if type(result) is not type([]):
            return None
        for tenant in result:
            if str(tenant['subscriber']) == str(subId):
                return str(tenant['id'])
        return None

    def subscriberCreate(self, index, subscriber_info = None, volt_subscriber_info = None):
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        log.info('Creating tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        subId = self.xos.subscriberCreate(subscriber_info, volt_subscriber_info)
        return subId

    def subscriberDelete(self, index, subId = '', voltId = '', subscriber_info = None, volt_subscriber_info = None):
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        log.info('Deleting tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        self.xos.subscriberDelete(volt_subscriber_info['account_num'], subId = subId, voltId = voltId)

    def subscriberId(self, index):
        volt_subscriber_info = self.volt_subscriber_info[index]
        return self.xos.subscriberId(volt_subscriber_info['account_num'])
