
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
            xos_host = xos_endpoints[0]
            xos_port = xos_endpoints[1]
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

    '''
    @method search_dictionary
    @Description: Searches for a key in the provided nested dictionary
    @params: input_dict = dictionary to be searched
             search_key = name of the key to be searched for
    returns two values: search_key value and status of the search.
             True if found (False when not found)

    '''
    def search_dictionary(self, input_dict, search_key):
        input_keys = input_dict.keys()
        key_value = ''
        found = False
        for key in input_keys:
            if key == search_key:
               key_value = input_dict[key]
               found = True
               break
            elif type(input_dict[key]) == dict:
                 key_value, found = self.search_dictionary(input_dict[key],search_key)
                 if found == True:
                    break
            elif type(input_dict[key]) == list:
                 if not input_dict[key]:
                    found = False
                    break
                 for item in input_dict[key]:
                     if isinstance(item, dict):
                        key_value, found = self.search_dictionary(item, search_key)
                        if found == True:
                           break
        return key_value,found

    '''
    @method getFieldValueFromDict
    @params : search_dict - Dictionary to be searched
             field - Key to be searched for (ex: account_num)
    @Returns: Returns the value of the Key that was provided
    '''
    def getFieldValueFromDict(self,search_dict, field):
        results = ''
        found = False
        input_keys = search_dict.keys()
        for key in input_keys:
            print "key...", key
            if key == field:
               results = search_dict[key]
               if not results:
                  found = True
                  break
            elif type(search_dict[key]) == dict:
                 results, found = self.search_dictionary(search_dict[key],field)
                 if found == True:
                    break
            elif type(search_dict[key]) == list:
                 if not search_dict[key]:
                    found = False
                    continue
                 for item in search_dict[key]:
                     if isinstance(item, dict):
                        results, found = self.search_dictionary(item, field)
                        if found == True:
                           break
            if results:
               break

        return results

    def getSubscriberId(self, subscriberList, account_num):
        subscriberId = 0
        subscriberInfo = None
        for subscriber in subscriberList:
            if str(subscriber['service_specific_id']) == str(account_num):
                subscriberId = self.getFieldValueFromDict(subscriber, 'id')
                subscriberInfo = subscriber
                break
        return subscriberInfo, subscriberId

    def getVoltId(self, result, subInfo, s_tag = None, c_tag = None):
        subscribed_link_ids_list = self.getFieldValueFromDict(subInfo,
                                                              'subscribed_links_ids')
        if len(subscribed_link_ids_list) > 0:
            subscribed_link_ids = subscribed_link_ids_list[0]
            service_link = self.restApi.ApiChameleonGet('CH_CORE_SERVICELINK',
                                                        subscribed_link_ids)
            assert_not_equal(service_link, None)
            provider_service_instance_id = service_link.get('provider_service_instance_id',
                                                            None)
            assert_not_equal(provider_service_instance_id, None)
            return provider_service_instance_id

        #find the tenant for the s_tag/c_tag
        if s_tag is None or c_tag is None:
            return None

        if result is None:
            result = self.restApi.ApiGet('VOLT_TENANT')
            result = result['items']

        tenant = filter(lambda t: int(t['s_tag']) == int(s_tag) and \
                        int(t['c_tag']) == int(c_tag), result)
        if not tenant:
            return None

        return tenant[0]['id']

    def getProviderInstance(self, info):
        return info['id']
        provided_link_ids_list = self.getFieldValueFromDict(info,
                                                            'provided_links_ids')
        assert_not_equal(provided_link_ids_list, None)
        assert_not_equal(len(provided_link_ids_list), 0)
        provided_link_ids = provided_link_ids_list[0]
        service_link = self.restApi.ApiChameleonGet('CH_CORE_SERVICELINK',
                                                    provided_link_ids)
        if service_link is None:
            return None
        provider_service_instance_id = service_link.get('provider_service_instance_id',
                                                        None)
        assert_not_equal(provider_service_instance_id, None)
        return provider_service_instance_id

    def linkTenant(self, subId, tenant_info):
        result = self.restApi.ApiGet('VOLT_TENANT')['items']
        tenant = None
        for volt in result:
            if str(volt['c_tag']) == str(tenant_info['c_tag']):
                tenant = volt
                break
        assert_not_equal(tenant, None)
        volt_id = self.getFieldValueFromDict(tenant, 'id')
        provided_links_ids_list = self.getFieldValueFromDict(tenant,
                                                             'provided_links_ids')
        assert_not_equal( len(provided_link_ids_list), 0)
        provided_link_ids = provided_link_ids_list[0]
        subscribed_link_ids_list = self.getFieldValueFromDict(tenant,
                                                              'subscribed_links_ids')
        assert_not_equal(len(subscribed_link_ids_list), 0)
        subscribed_link_ids = subscribed_link_ids_list[0]
        service_link = self.restApi.ApiChameleonGet('CH_CORE_SERVICELINK',
                                                    provided_link_ids)
        assert_not_equal(service_link, None)
        provider_service_instance_id = service_link.get('provider_service_instance_id',
                                                        None)
        assert_not_equal(provider_service_instance_id, None)
        service_dict = dict(subscriber_service_instance_id = subId)
        result = self.restApi.ApiChameleonPut('CH_CORE_SERVICELINK',
                                              service_dict,
                                              provided_link_ids)
        assert_equal(result, True)
        return provider_service_instance_id
        # service_link_dict = self.restApi.ApiChameleonGet('CH_CORE_SERVICELINK',
        #                                                  subscribed_link_ids)
        # assert_not_equal(service_link_dict, None)
        # vsg_tenant = service_link_dict.get('provider_service_instance_id', None)
        # assert_not_equal(vsg_tenant, None)
        # vsg_result = self.restApi.ApiChameleonGet('VSG_TENANT',
        #                                           vsg_tenant)
        # assert_not_equal(vsg_result, None)
        # vsg_instance = vsg_result.get('instance_id', None)
        # assert_not_equal(vsg_instance, None)
        # instance_result = self.restApi.ApiChameleonGet('CH_CORE_INSTANCES',
        #                                                vsg_instance)
        # assert_equal(instance_result, True)

    def subscriberCreate(self, subscriber_info, volt_subscriber_info):
        subId = ''
        try:
            result = self.restApi.ApiPost('VOLT_SUBSCRIBER', subscriber_info)
            assert_equal(result, True)
            result = self.restApi.ApiGet('VOLT_SUBSCRIBER')
            assert_not_equal(result, None)
            result = result['items']
            _, subId = self.getSubscriberId(result,
                                            volt_subscriber_info['service_specific_id'])
            assert_not_equal(subId, '0')
            log.info('Subscriber ID for account num %s = %s' %(str(volt_subscriber_info['service_specific_id']), subId))
            volt_tenant = volt_subscriber_info['voltTenant']
            result = self.restApi.ApiPost('VOLT_TENANT', volt_tenant)
            assert_equal(result, True)
            volt_id = self.linkTenant(subId, volt_tenant)
            log.info('Subscriber create with ctag %s, stag %s, volt id %s' %(str(volt_tenant['c_tag']),
                                                                             str(volt_tenant['s_tag']),
                                                                             str(volt_id)))
        finally:
            return subId

    def subscriberDelete(self, account_num, s_tag = None, c_tag = None, subId = '', voltId = ''):
        result = self.restApi.ApiGet('VOLT_SUBSCRIBER')
        assert_not_equal(result, None)
        result = result['items']
        if not subId:
            #get the subscriber id first
            subInfo, subId = self.getSubscriberId(result, account_num)
            assert_not_equal(subId, '0')
        else:
            subInfo, currentSubId = self.getSubscriberId(result, account_num)
            assert_not_equal(currentSubId, '0')
            #assert_equal(subId, currentSubId)
            subId = self.getFieldValueFromDict(subInfo, 'id')
        if not voltId:
            #get the volt id for the subscriber
            result = self.restApi.ApiGet('VOLT_TENANT')
            assert_not_equal(result, None)
            result = result['items']
            voltId = self.getVoltId(result, subInfo, s_tag = s_tag, c_tag = c_tag)
            assert_not_equal(voltId, None)
        log.info('Deleting VOLT Tenant ID %s for subscriber %s' %(voltId, subId))
        status = self.restApi.ApiChameleonDelete('VOLT_TENANT', voltId)
        assert_equal(status, True)
        log.info('Deleting subscriber ID %s for account num %s' %(subId, str(account_num)))
        status = self.restApi.ApiChameleonDelete('VOLT_SUBSCRIBER', subId)
        assert_equal(status, True)

    def subscriberId(self, account_num):
        result = self.restApi.ApiGet('VOLT_SUBSCRIBER')
        assert_not_equal(result, None)
        result = result['items']
        _, subId = self.getSubscriberId(result, account_num)
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
        self.tenant_map = {}
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
        self.tenant_map[account_num] = (s_tag, c_tag)
        return self.subscriber_map[subId]

    def getConfig(self):
        features =  {
            'cdn_enable': True,
            'uplink_speed': 1000000000,
            'downlink_speed': 1000000000,
            'enable_uverse': True,
            'status': 'enabled'
        }
        subscriber_map = []
        for i in xrange(self.num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, _, _ = self.getCredentials(subId)
            identity = { 'service_specific_id' : str(account_num),
                         'name' : 'My House {}'.format(i)
                         }
            sub_data = [ (k, v) for d in (features, identity) \
                         for k, v in d.iteritems() ]
            sub_info = dict(sub_data)
            subscriber_map.append(sub_info)

        return subscriber_map

    def getVoltInfo(self, account_num):
        num = int(account_num)
        if num in self.tenant_map:
            return self.tenant_map[num]
        return None, None

    def getVoltConfig(self):
        voltSubscriberMap = []
        for i in xrange(self.num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, s_tag, c_tag = self.getCredentials(subId)
            voltSubscriberInfo = {}
            voltSubscriberInfo['voltTenant'] = dict(s_tag = str(s_tag),
                                                    c_tag = str(c_tag))
            voltSubscriberInfo['service_specific_id'] = account_num
            voltSubscriberMap.append(voltSubscriberInfo)

        return voltSubscriberMap

    def getVoltId(self, subInfo):
        s_tag, c_tag = self.getVoltInfo(subInfo['service_specific_id'])
        return self.xos.getVoltId(None, subInfo, s_tag = s_tag, c_tag = c_tag)

    def getProviderInstance(self, tenant_info):
        return self.xos.getProviderInstance(tenant_info)

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
        self.xos.subscriberDelete(volt_subscriber_info['service_specific_id'], s_tag = s_tag, c_tag = c_tag, subId = subId, voltId = voltId)

    def subscriberId(self, index):
        volt_subscriber_info = self.volt_subscriber_info[index]
        return self.xos.subscriberId(volt_subscriber_info['service_specific_id'])
