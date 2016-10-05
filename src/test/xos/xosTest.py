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
import unittest
import subprocess
from docker import Client
from itertools import chain
from nose.tools import *
from scapy.all import *
from CordContainer import *
import threading
import time
import os
import json
import pexpect
import urllib
log.setLevel('INFO')

flatten = lambda l: chain.from_iterable(l)

class xos_exchange(unittest.TestCase):

    dckr = Client()
    test_path = os.path.dirname(os.path.realpath(__file__))
    XOS_BASE_CONTAINER_IMAGE = 'xosproject/xos-base:latest'
    XOS_BASE_CONTAINER_NAME = 'xos-base'
    XOS_BASE_CONTAINER_PORTS = [8000]
    XOS_SYN_OPENSTACK_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-openstack'
    XOS_SYN_OPENSTACK_CONTAINER_NAME = 'xos-synchronizer'
    XOS_SYN_OPENSTACK_CONTAINER_PORTS = [8000]
    XOS_POSTGRESQL_CONTAINER_IMAGE = 'xosproject/xos-postgres'
    XOS_POSTGRESQL_CONTAINER_NAME = 'xos-db-postgres'
    XOS_POSTGRESQL_CONTAINER_PORTS = [5432]
    XOS_SYNDICATE_MS_CONTAINER_IMAGE = 'xosproject/syndicate-ms'
    XOS_SYNDICATE_MS_CONTAINER_NAME = 'xos-syndicate-ms'
    XOS_SYNDICATE_MS_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vtr'
    XOS_SYNCHRONIZER_VTR_CONTAINER_NAME = 'xos-synchronizer-vtr'
    XOS_SYNCHRONIZER_VTR_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vsg'
    XOS_SYNCHRONIZER_VSG_CONTAINER_NAME = 'xos-synchronizer-vsg'
    XOS_SYNCHRONIZER_VSG_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-onos'
    XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME = 'xos-synchronizer-onos'
    XOS_SYNCHRONIZER_ONOS_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-fabric'
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME = 'xos-synchronizer-fabric'
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vtn'
    XOS_SYNCHRONIZER_VTN_CONTAINER_NAME = 'xos-synchronizer-vtn'
    XOS_SYNCHRONIZER_VTN_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-onboarding'
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME = 'xos-synchronizer-onboarding'
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_PORTS = [8080]
    XOS_API_ERROR_STRING_MATCH_1 = 'The resource you\'re looking for doesn\'t exist'
    XOS_API_ERROR_STRING_MATCH_2 = 'Application Error'
    XOS_API_UTILS_POST_LOGIN = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/login/'
    #XOS_API_UTILS_GET_PORTFORWARDING = 'https://private-anon-873978896e-xos.apiary-mock.com/api/portforwarding/port'
    XOS_API_UTILS_GET_PORT_FORWARDING = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/portforwarding/'
    XOS_API_UTILS_GET_SLICES_PLUS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/slicesplus/'
    XOS_API_UTILS_GET_SYNCHRONIZER = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/synchronizer/'
    XOS_API_UTILS_GET_ONBOARDING_STATUS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/onboarding/service/ready'
    XOS_API_UTILS_POST_TOSCA_RECIPE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/tosca/run/'
    XOS_API_UTILS_GET_SSH_KEYS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/utility/sshkeys/'
    XOS_API_TENANT_GET_ALL_SUBSCRIBERS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/'
    XOS_API_TENANT_GET_SUBSCRIBER_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/'
    XOS_API_TENANT_DELETE_SUBSCRIBER = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/'
    XOS_API_TENANT_GET_SUBSCRIBER_FEATURE_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/'
    XOS_API_TENANT_GET_READ_SUBSCRIBER_UPLINK_SPEED = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/'
    XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_UPLINK_SPEED = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/'
    XOS_API_TENANT_GET_READ_SUBSCRIBER_DOWNLINK_SPEED = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/'
    XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_DOWNLINK_SPEED = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/'
    XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_CDN = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/'
    XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_CDN = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/'
    XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_UVERSE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/'
    XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_UVERSE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/'
    XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_STATUS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/'
    XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_STATUS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/'
    XOS_API_TENANT_GET_ALL_TRUCKROLL = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/'
    XOS_API_TENANT_POST_CREATE_TRUCKROLL = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/'
    XOS_API_TENANT_GET_TRUCKROLL_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/'
    XOS_API_TENANT_DELETE_TRUCKROLL_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/'
    XOS_API_TENANT_GET_ALL_vOLT = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/'
    XOS_API_TENANT_POST_CREATE_vOLT = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/'
    XOS_API_TENANT_GET_vOLT_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/'
    XOS_API_TENANT_GET_ALL_ONOS_APPS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/onos/app/'
    XOS_API_SERVICE_GET_ALL_EXAMPLE_SERVICE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/service/exampleservice/'
    XOS_API_SERVICE_GET_ALL_ONOS_SERVICE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/service/onos/'
    XOS_API_SERVICE_GET_ALL_vSG = 'https://private-anon-873978896e-xos.apiary-mock.com/api/service/vsg/'
    XOS_API_CORE_GET_ALL_DEPLOYMENTS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/'
    XOS_API_CORE_POST_CREATE_DEPLOYMENTS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/'
    XOS_API_CORE_GET_DEPLOYMENT_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/'
    XOS_API_CORE_DELETE_DEPLOYMENTS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/'
    XOS_API_CORE_GET_ALL_FLAVORS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavoryys/id/'
    XOS_API_CORE_POST_CREATE_FLAVORS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/'
    XOS_API_CORE_GET_FLAVOR_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/'
    XOS_API_CORE_DELETE_FLAVORS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/'
    XOS_API_CORE_GET_ALL_INSTANCES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/'
    XOS_API_CORE_POST_CREATE_INSTANCES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/?no_hyperlinks=1'
    XOS_API_CORE_GET_INSTANCE_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/'
    XOS_API_CORE_DELETE_INSTANCES= 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/'
    XOS_API_CORE_GET_ALL_NODES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/nodes/id/'
    XOS_API_CORE_GET_ALL_SERVICES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/'
    XOS_API_CORE_POST_CREATE_SERVICE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/'
    XOS_API_CORE_GET_SERVICE_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/'
    XOS_API_CORE_DELETE_SERVICE = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/'
    XOS_API_CORE_GET_ALL_SITES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/'
    XOS_API_CORE_GET_SITES_DETAILS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/id/'
    XOS_API_CORE_GET_ALL_SLICES = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/slices/id/'
    XOS_API_CORE_GET_ALL_USERS = 'https://private-anon-873978896e-xos.apiary-mock.com/api/core/users/id/'


    def setUp(self):
        ''' Activate the XOS containers'''
        self.maxDiff = None ##for assert_equal compare outputs on failure

    def tearDown(self):
        '''Deactivate the xos containers'''
        log.info('Tear down setup')
        self.CURRENT_PORT_NUM = 4

    def exists(self, name):
        return '/{0}'.format(name) in list(flatten(n['Names'] for n in self.dckr.containers()))


    def img_exists(self, image):
        cnt = filter(lambda c: c['Image'] == image, self.dckr.containers())
        return image in [ctn['RepoTags'][0] if ctn['RepoTags'] else '' for ctn in self.dckr.images()]

    def xos_containers_check(self, name, image):
           if self.exists(name) != True:
              if name == self.XOS_BASE_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosBase = Xos_base(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYN_OPENSTACK_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSynchronizerOpenstack(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_POSTGRESQL_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosPostgresql = XosPostgresql(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNDICATE_MS_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSyndicateMs = XosSyndicateMs(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSyncVtr(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSyncVsg(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSyncOnos(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSyncFabric(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSyncVtn(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = XosSynchronizerOnboarding(prefix = Container.IMAGE_PREFIX, update = False)
              if self.img_exists(image) != True:
                 log.info('%s container image is not built on host' %name)
                 assert_equal(False, True)
              if self.exists(name) != True:
                 log.info('%s container image is build on host' %name)
                 assert_equal(False, True)

    def container_status(self, image, name):
        ''' This function is checking that container is up and running'''
        self.xos_containers_check(name, image)
        container_info = self.dckr.containers(filters ={'name':name, 'status':'running'})
        log.info('Xos container info= %s' %container_info)

        if not container_info:
           ## forcely failing test case
           log.info('%s container is not running, container info %s' %(name,container_info))
           assert_equal(False, True)
        else:
           container_status = container_info[0]['Status']
           log.info('Xos container status= %s' %container_status)
           assert_equal(container_status.split(' ')[0], 'Up')
           return container_info

    def container_ping(self, image, name):
        ''' This function is checking if container is reachable '''
        container_info = self.container_status(image= image, name= name)
        container_ip = container_info[0]['NetworkSettings']['Networks']['bridge']['IPAddress']
        ping_status = os.system('ping {} -c 3'.format(container_ip))
        if ping_status != 0:
           log.info('%s container is not reachable, response %s = '%(name,ping_status))
           assert_equal(ping_status, 0)
        log.info('%s container is not reachable, response = %s'%(name,ping_status))
        assert_equal(ping_status, 0)

    def container_listening_ports_info(self, image, name, ports_list):
        ''' This function is checking that container ports are as excpeted '''
        container_public_ports = []
        container_info = self.container_status(image= image, name= name)
        container_ports = container_info[0]['Ports']
        container_public_ports.append(container_ports[0]['PublicPort'])
        log.info('%s container is listening on these ports = %s'%(name,container_ports))
        log.info('%s container is listening on these public ports = %s'%(name,container_public_ports))
        for n in range(0,len(ports_list)):
            port = ports_list[n]
            if port in container_public_ports:
               assert_equal(True, True)
            else:
               log.info('%s container is not listening on %s port which is not expected' %(name,n))
               assert_equal(False, True)

    def container_stop_start(self):
        ''' This function is checking if container is stopped and started running again'''

    def validate_url_response_data(self, url):
        ''' This function is checking url responce and cross check errors on it output '''
        response = urllib.urlopen(url)
        data = response.read()
        log.info('This is PORT FORWARDING URL reponse data {}'.format(data))
        if not data:
           log.info('{} Url did not returned any output from opencloud setup'.format(url))
           assert_equal(True, False)
        if self.XOS_API_ERROR_STRING_MATCH_1 in data:
           log.info('Not an expected output from url'.format(url))
           assert_equal(True, False)
        if self.XOS_API_ERROR_STRING_MATCH_2 in data:
           log.info('Not an expected output from url'.format(url))
           assert_equal(True, False)

    @nottest
    def test_xos_base_container_status(self):
        self.container_status(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME)

    @nottest
    def test_xos_base_container_ping(self):
        self.container_ping(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME)

    @nottest
    def test_xos_base_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME,
                                             ports_list = self.XOS_BASE_CONTAINER_PORTS)

    def test_xos_sync_openstack_container_status(self):
        self.container_status(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE, name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME)

    def test_xos_sync_openstack_container_ping(self):
        self.container_ping(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE, name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME)

    def test_xos_sync_openstack_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE,
                                            name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME,
                                            ports_list = self.XOS_SYN_OPENSTACK_CONTAINER_PORTS)

    def test_xos_postgresql_container_status(self):
        self.container_status(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE, name = self.XOS_POSTGRESQL_CONTAINER_NAME)

    def test_xos_postgresql_container_ping(self):
        self.container_ping(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE, name = self.XOS_POSTGRESQL_CONTAINER_NAME)

    def test_xos_postgresql_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE,
                                            name = self.XOS_POSTGRESQL_CONTAINER_NAME,
                                            ports_list = self.XOS_POSTGRESQL_CONTAINER_PORTS)

    def test_xos_syndicate_ms_container_status(self):
        self.container_status(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE, name = self.XOS_SYNDICATE_MS_CONTAINER_NAME)

    def test_xos_syndicate_ms_container_ping(self):
        self.container_ping(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE, name = self.XOS_SYNDICATE_MS_CONTAINER_NAME)

    def test_xos_syndicate_ms_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE,
                                            name = self.XOS_SYNDICATE_MS_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNDICATE_MS_CONTAINER_PORTS)

    @nottest
    def test_xos_sync_vtr_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME)

    @nottest
    def test_xos_sync_vtr_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME)

    @nottest
    def ztest_xos_sync_vtr_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VTR_CONTAINER_PORTS)

    @nottest
    def test_xos_sync_vsg_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME)

    @nottest
    def test_xos_sync_vsg_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME)

    @nottest
    def test_xos_sync_vsg_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VSG_CONTAINER_PORTS)
    @nottest
    def test_xos_sync_onos_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME)

    @nottest
    def test_xos_sync_onos_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME)

    @nottest
    def test_xos_sync_onos_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_PORTS)
    @nottest
    def test_xos_sync_fabric_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME)

    @nottest
    def test_xos_sync_fabric_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME)

    @nottest
    def test_xos_sync_fabric_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_PORTS)
    @nottest
    def test_xos_sync_vtn_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME)

    @nottest
    def test_xos_sync_vtn_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME)

    @nottest
    def test_xos_sync_vtn_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VTN_CONTAINER_PORTS)

    def test_xos_sync_onboarding_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE)

    def test_xos_sync_onboarding_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE)

    def test_xos_sync_onboarding_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_PORTS)

    def test_xos_api_post_login(self):
        response = urllib.urlopen(self.XOS_API_UTILS_POST_LOGIN)
        data = response.read()

    def test_xos_api_get_utils_port_forwarding(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_GET_PORT_FORWARDING)

    def test_xos_api_get_utils_slices_plus(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_GET_SLICES_PLUS)

    def test_xos_api_get_utils_synchronizer(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_GET_SYNCHRONIZER)

    def test_xos_api_get_utils_onboarding_status(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_GET_ONBOARDING_STATUS)

    def test_xos_api_post_utils_tosca_recipe(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_POST_TOSCA_RECIPE)

    def test_xos_api_get_utils_ssh_keys(self):
        self.validate_url_response_data(url = self.XOS_API_UTILS_GET_SSH_KEYS)

    def test_xos_api_get_tenant_all_subscribers(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_ALL_SUBSCRIBERS)

    def test_xos_api_get_tenant_subscribers_details(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_SUBSCRIBER_DETAILS)

    def test_xos_api_get_tenant_subscriber_delete(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_DELETE_SUBSCRIBER)

    def test_xos_api_get_tenant_subscribers_feature_details(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_SUBSCRIBER_FEATURE_DETAILS)

    def test_xos_api_get_tenant_read_subscribers_feature_uplink_speed(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_READ_SUBSCRIBER_UPLINK_SPEED)

    def test_xos_api_tenant_put_update_subscribers_feature_uplink_speed(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_UPLINK_SPEED)

    def test_xos_api_get_tenant_read_subscribers_feature_downlink_speed(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_READ_SUBSCRIBER_DOWNLINK_SPEED)

    def test_xos_api_tenant_put_update_subscribers_feature_downlink_speed(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_DOWNLINK_SPEED)

    def test_xos_api_get_tenant_read_subscribers_feature_cdn(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_CDN)

    def test_xos_api_tenant_put_update_subscribers_feature_cdn(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_CDN)

    def test_xos_api_get_tenant_read_subscribers_feature_uverse(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_UVERSE)

    def test_xos_api_tenant_put_update_subscribers_feature_uverse(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_UVERSE)

    def test_xos_api_get_tenant_read_subscribers_feature_status(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_READ_SUBSCRIBER_FEATURE_STATUS)

    def test_xos_api_tenant_put_update_subscribers_feature_status(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_PUT_UPDATE_SUBSCRIBER_FEATURE_STATUS)

    def test_xos_api_tenant_get_all_truckroll(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_ALL_TRUCKROLL)

    def test_xos_api_tenant_post_create_truckroll(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_POST_CREATE_TRUCKROLL)

    def test_xos_api_tenant_get_truckroll_details(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_TRUCKROLL_DETAILS)

    def test_xos_api_tenant_delete_trucroll(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_DELETE_TRUCKROLL_DETAILS)

    def test_xos_api_tenant_get_all_volt(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_ALL_vOLT)

    def test_xos_api_tenant_post_create_vOLT(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_POST_CREATE_vOLT)

    def test_xos_api_tenant_get_volt_details(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_vOLT_DETAILS)

    def test_xos_api_tenant_get_all_onos_apps(self):
        self.validate_url_response_data(url = self.XOS_API_TENANT_GET_ALL_ONOS_APPS)

    def test_xos_api_service_get_all_example_service(self):
        self.validate_url_response_data(url = self.XOS_API_SERVICE_GET_ALL_EXAMPLE_SERVICE)

    def test_xos_api_service_get_all_onos_service(self):
        self.validate_url_response_data(url = self.XOS_API_SERVICE_GET_ALL_ONOS_SERVICE)

    def test_xos_api_service_get_all_vsg(self):
        self.validate_url_response_data(url = self.XOS_API_SERVICE_GET_ALL_vSG)

    def test_xos_api_core_get_all_deployments(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_DEPLOYMENTS)

    def test_xos_api_core_post_create_deployments(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_POST_CREATE_DEPLOYMENTS)

    def test_xos_api_core_get_deployment_details(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_DEPLOYMENT_DETAILS)

    def test_xos_api_core_delete_deployment(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_DELETE_DEPLOYMENTS)

    def test_xos_api_core_get_all_flavors(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_FLAVORS)

    def test_xos_api_core_post_create_flavors(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_POST_CREATE_FLAVORS)

    def test_xos_api_core_get_flavor_details(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_FLAVOR_DETAILS)

    def test_xos_api_core_delete_flavors(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_DELETE_FLAVORS)

    def test_xos_api_core_get_all_instances(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_INSTANCES)

    def test_xos_api_core_post_create_instances(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_POST_CREATE_INSTANCES)

    def test_xos_api_core_get_instance_details(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_INSTANCE_DETAILS)

    def test_xos_api_core_delete_instance(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_DELETE_INSTANCES)

    def test_xos_api_core_get_all_nodes(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_NODES)

    def test_xos_api_core_get_all_services(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_SERVICES)

    def test_xos_api_core_post_create_service(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_POST_CREATE_SERVICE)

    def test_xos_api_core_get_service_details(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_SERVICE_DETAILS)

    def test_xos_api_core_delete_service(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_DELETE_SERVICE)

    def test_xos_api_core_get_all_sites(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_SITES)

    def test_xos_api_core_get_site_details(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_SITES_DETAILS)

    def test_xos_api_core_get_all_slices(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_SLICES)

    def test_xos_api_core_get_all_users(self):
        self.validate_url_response_data(url = self.XOS_API_CORE_GET_ALL_USERS)

